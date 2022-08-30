// SPDX-License-Identifier: GPL-2.0
/*
 * xdpmap_fifo.c: FIFO map for queueing XDP frames
 *
 * Copyright (C) 2022, Toke Høiland-Jørgensen <toke@toke.dk>
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <net/xdp.h>

#define XDP_FIFO_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK)

struct bpf_xdp_fifo_bucket {
	struct xdp_frame *head, *tail;
	spinlock_t lock;
	u32 elem_count;
};

struct bpf_xdp_fifo {
	struct bpf_map map;
	struct bpf_xdp_fifo_bucket *buckets;
	unsigned long num_buckets;
};

static struct bpf_xdp_fifo *bpf_xdp_fifo(struct bpf_map *map)
{
	return container_of(map, struct bpf_xdp_fifo, map);
}

/* Called from syscall */
static int xdp_fifo_alloc_check(union bpf_attr *attr)
{
	if (!bpf_capable())
		return -EPERM;

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size != 4 ||
	    attr->map_flags & ~XDP_FIFO_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (sizeof(struct bpf_xdp_fifo_bucket) > U32_MAX / attr->map_extra)
		return -E2BIG;

	return 0;
}

static struct bpf_map *xdp_fifo_alloc(union bpf_attr *attr)
{
	int i, numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_xdp_fifo *fifo;

	fifo = bpf_map_area_alloc(sizeof(*fifo), numa_node);
	if (!fifo)
		return ERR_PTR(-ENOMEM);


	fifo->num_buckets = attr->map_extra;
	fifo->buckets = bpf_map_area_alloc(sizeof(*fifo->buckets) * fifo->num_buckets, numa_node);
	if (!fifo->buckets) {
		bpf_map_area_free(fifo);
		return ERR_PTR(-ENOMEM);
	}

	bpf_map_init_from_attr(&fifo->map, attr);
	for (i = 0; i < fifo->num_buckets; i++)
		spin_lock_init(&fifo->buckets[i].lock);

	return &fifo->map;
}

static void xdp_fifo_purge(struct bpf_xdp_fifo *fifo)
{
	int i;

	for (i = 0; i < fifo->num_buckets; i++) {
		struct bpf_xdp_fifo_bucket *bucket;
		struct xdp_frame *frame, *next;

		bucket = &fifo->buckets[i];
		frame = bucket->head;

		while (frame) {
			next = frame->next;
			xdp_return_frame(frame);
			frame = next;
		}
	}
}

static void xdp_fifo_free(struct bpf_map *map)
{
	struct bpf_xdp_fifo *fifo = bpf_xdp_fifo(map);

	synchronize_rcu();

	xdp_fifo_purge(fifo);
	bpf_map_area_free(fifo->buckets);
	bpf_map_area_free(fifo);
}

/* Called from syscall */
static void *xdp_fifo_lookup_elem_sys(struct bpf_map *map, void *key)
{
	struct bpf_xdp_fifo *fifo = bpf_xdp_fifo(map);
	struct bpf_xdp_fifo_bucket *bucket;
	u32 index = *(u32 *)key;

	if (index >= fifo->num_buckets)
		return ERR_PTR(-ENOENT);

	bucket = &fifo->buckets[index];

	return &bucket->elem_count;
}

/* Called from eBPF program */
static void *xdp_fifo_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

/* Called from syscall or from eBPF program */
static int xdp_fifo_update_elem(struct bpf_map *map, void *key, void *value,
			       u64 flags)
{
	return -EOPNOTSUPP;
}

/* Called from syscall or from eBPF program */
static int xdp_fifo_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

/* Called from syscall */
static int xdp_fifo_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_xdp_fifo *fifo = bpf_xdp_fifo(map);
	u64 nkey = 0;

	if (!key)
		goto out;

	nkey = *(u64 *) key + 1;
	if (nkey >= fifo->num_buckets)
		return -ENOENT;
out:
	*(u64 *) next_key = nkey;
	return 0;
}

int xdp_fifo_map_enqueue(struct bpf_map *map, struct xdp_frame *xdpf, u64 index)
{
	struct bpf_xdp_fifo *fifo = bpf_xdp_fifo(map);
	struct bpf_xdp_fifo_bucket *bucket;
	int err = -EOVERFLOW;

	if (index >= fifo->num_buckets)
		return -E2BIG;

	bucket = &fifo->buckets[index];

	/* called under local_bh_disable() so no need to use irqsave variant */
	spin_lock(&bucket->lock);

	if (unlikely(bucket->elem_count >= fifo->map.max_entries))
		goto out;

	if (likely(!bucket->head)) {
		bucket->head = xdpf;
		bucket->tail = xdpf;
	} else {
		bucket->tail->next = xdpf;
		bucket->tail = xdpf;
	}

	bucket->elem_count++;
	err = 0;

out:
	spin_unlock(&bucket->lock);
	return err;
}

struct xdp_frame *xdp_fifo_map_dequeue(struct bpf_map *map, u64 flags, u64 *rank)
{
	struct bpf_xdp_fifo *fifo = bpf_xdp_fifo(map);
	struct bpf_xdp_fifo_bucket *bucket;
	struct xdp_frame *frm;
	u64 index = flags;

	if (index >= fifo->num_buckets)
		return NULL;

	bucket = &fifo->buckets[index];

	spin_lock(&bucket->lock);

	frm = bucket->head;
	if (!frm)
		goto out;

	bucket->head = frm->next;
	frm->next = NULL;

	if (bucket->tail == frm)
		bucket->tail = bucket->head;

	bucket->elem_count--;

out:
	spin_unlock(&bucket->lock);
	return frm;
}


static int xdp_fifo_map_redirect(struct bpf_map *map, u64 index, u64 flags)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	const u64 action_mask = XDP_ABORTED | XDP_DROP | XDP_PASS | XDP_TX;

	/* Lower bits of the flags are used as return code on lookup failure */
	if (unlikely(flags & ~action_mask))
		return XDP_ABORTED;

	ri->tgt_value = NULL;
	ri->tgt_index = index;
	ri->map_id = map->id;
	ri->map_type = map->map_type;
	ri->flags = flags;
	WRITE_ONCE(ri->map, map);
	return XDP_REDIRECT;
}

BTF_ID_LIST_SINGLE(xdp_fifo_btf_ids, struct, bpf_xdp_fifo)
const struct bpf_map_ops xdp_fifo_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = xdp_fifo_alloc_check,
	.map_alloc = xdp_fifo_alloc,
	.map_free = xdp_fifo_free,
	.map_lookup_elem_sys_only = xdp_fifo_lookup_elem_sys,
	.map_lookup_elem = xdp_fifo_lookup_elem,
	.map_update_elem = xdp_fifo_update_elem,
	.map_delete_elem = xdp_fifo_delete_elem,
	.map_get_next_key = xdp_fifo_get_next_key,
	.map_btf_id = &xdp_fifo_btf_ids[0],
	.map_redirect = xdp_fifo_map_redirect,
};
