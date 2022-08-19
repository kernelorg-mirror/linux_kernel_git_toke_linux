// SPDX-License-Identifier: GPL-2.0
/*
 * pifomap_rbtree.c: PIFO map based on RB-tree
 *
 * Adapted from Cong Wang's pifo_rb[0] to work with xdp_frames and use the same
 * API as the PIFO map.
 *
 * [0] https://lore.kernel.org/r/20220602041028.95124-4-xiyou.wangcong@gmail.com
 *
 * Copyright (C) 2022, ByteDance, Cong Wang <cong.wang@bytedance.com>
 * Copyright (C) 2022, Toke Høiland-Jørgensen <toke@toke.dk>
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/rbtree.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <net/xdp.h>

#define PIFO_RB_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK)

#define rb_to_xdp(rb) rb_entry_safe(rb, struct xdp_frame, rbnode)
#define xdp_rb_first(root) rb_to_xdp(rb_first(root))
#define xdp_rb_last(root)  rb_to_xdp(rb_last(root))
#define xdp_rb_next(xdp)   rb_to_xdp(rb_next(&(xdp)->rbnode))
#define xdp_rb_prev(xdp)   rb_to_xdp(rb_prev(&(xdp)->rbnode))

#define xdp_rbtree_walk_safe(xdp, tmp, root)				\
		for (xdp = xdp_rb_first(root);					\
		     tmp = xdp ? xdp_rb_next(xdp) : NULL, (xdp != NULL);	\
		     xdp = tmp)


struct bpf_pifo_rb {
	struct bpf_map map;
	struct rb_root root;
	raw_spinlock_t lock;
	struct rb_node node;
	u64 rank;
	struct list_head list;
	unsigned long num_queued;
};

struct pifo_rb_cb {
	struct qdisc_skb_cb qdisc_cb;
	u64 rank;
};

static struct bpf_pifo_rb *bpf_pifo_rb(struct bpf_map *map)
{
	return container_of(map, struct bpf_pifo_rb, map);
}

static bool pifo_rb_map_is_full(struct bpf_pifo_rb *pifo)
{
	return pifo->num_queued >= pifo->map.max_entries;
}

static void xdp_rbtree_purge(struct rb_root *root)
{
	struct rb_node *p = rb_first(root);

	while (p) {
		struct xdp_frame *frm = rb_entry(p, struct xdp_frame, rbnode);

		p = rb_next(p);
		rb_erase(&frm->rbnode, root);
		xdp_return_frame(frm);
	}
}


#define PIFO_RB_MAX_SZ 1048576

/* Called from syscall */
static int pifo_rb_alloc_check(union bpf_attr *attr)
{
	if (!bpf_capable())
		return -EPERM;

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size != 4 ||
	    attr->map_flags & ~PIFO_RB_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (attr->max_entries > PIFO_RB_MAX_SZ)
		return -E2BIG;

	return 0;
}

static struct bpf_map *pifo_rb_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_pifo_rb *rb;

	rb = bpf_map_area_alloc(sizeof(*rb), numa_node);
	if (!rb)
		return ERR_PTR(-ENOMEM);

	memset(rb, 0, sizeof(*rb));
	bpf_map_init_from_attr(&rb->map, attr);
	raw_spin_lock_init(&rb->lock);
	rb->root = RB_ROOT;
	return &rb->map;
}

static void pifo_rb_free(struct bpf_map *map)
{
	struct bpf_pifo_rb *rb = bpf_pifo_rb(map);

	synchronize_rcu();

	xdp_rbtree_purge(&rb->root);
	bpf_map_area_free(rb);
}

static struct xdp_frame *xdp_rb_find(struct rb_root *root, u64 rank)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct xdp_frame *frm;

	while (*p) {
		parent = *p;
		frm = rb_to_xdp(parent);
		if (rank < frm->rank)
			p = &parent->rb_left;
		else if (rank > frm->rank)
			p = &parent->rb_right;
		else
			return frm;
	}
	return NULL;
}

/* Called from syscall */
static void *pifo_rb_lookup_elem_sys(struct bpf_map *map, void *key)
{
	return ERR_PTR(-ENOTSUPP);
}

/* Called from eBPF program */
static void *pifo_rb_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_pifo_rb *rb = bpf_pifo_rb(map);
	u64 rank = *(u64 *) key;

	return xdp_rb_find(&rb->root, rank);
}

/* Called from syscall or from eBPF program */
static int pifo_rb_update_elem(struct bpf_map *map, void *key, void *value,
			       u64 flags)
{
	return -ENOTSUPP;
}

/* Called from syscall or from eBPF program */
static int pifo_rb_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_pifo_rb *rb = bpf_pifo_rb(map);
	u64 rank = *(u64 *) key;
	struct xdp_frame *frm;

	frm = xdp_rb_find(&rb->root, rank);
	if (!frm)
		return -ENOENT;
	rb_erase(&frm->rbnode, &rb->root);
	xdp_return_frame(frm);
	return 0;
}

/* Called from syscall */
static int pifo_rb_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_pifo_rb *rb = bpf_pifo_rb(map);
	struct xdp_frame *frm;
	u64 rank;

	if (!key) {
		frm = xdp_rb_first(&rb->root);
		if (!frm)
			return -ENOENT;
		goto found;
	}
	rank = *(u64 *) key;
	frm = xdp_rb_find(&rb->root, rank);
	if (!frm)
		return -ENOENT;
	frm = xdp_rb_next(frm);
	if (!frm)
		return 0;
found:
	*(u64 *) next_key = frm->rank;
	return 0;
}

static int bpf_for_each_pifo_rb(struct bpf_map *map, bpf_callback_t callback_fn,
				void *callback_ctx, u64 flags)
{
	struct bpf_pifo_rb *rb = bpf_pifo_rb(map);
	struct xdp_frame *frm, *tmp;
	u32 num_elems = 0;
	u64 ret = 0;
	u64 key;

	if (flags != 0)
		return -EINVAL;

	xdp_rbtree_walk_safe(frm, tmp, &rb->root) {
		num_elems++;
		key = frm->rank;
		ret = callback_fn((u64)(long)map, key, (u64)(long)frm,
				  (u64)(long)callback_ctx, 0);
		/* return value: 0 - continue, 1 - stop and return */
		if (ret)
			break;
	}

	return num_elems;
}

static void xdp_rb_push(struct rb_root *root, struct xdp_frame *frm)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct xdp_frame *frm1;

	while (*p) {
		parent = *p;
		frm1 = rb_to_xdp(parent);
		if (frm->rank < frm1->rank)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&frm->rbnode, parent, p);
	rb_insert_color(&frm->rbnode, root);
}

int pifo_rb_map_enqueue(struct bpf_map *map, struct xdp_frame *xdpf, u64 index)
{
	struct bpf_pifo_rb *rb = bpf_pifo_rb(map);
	int err = -EOVERFLOW;

	/* called under local_bh_disable() so no need to use irqsave variant */
	raw_spin_lock(&rb->lock);

	if (unlikely(pifo_rb_map_is_full(rb)))
		goto out;

	xdpf->rank = index;
	xdp_rb_push(&rb->root, xdpf);
	rb->num_queued++;
	err = 0;

out:
	raw_spin_unlock(&rb->lock);
	return err;
}

struct xdp_frame *pifo_rb_map_dequeue(struct bpf_map *map, u64 flags, u64 *rank)
{
	struct bpf_pifo_rb *rb = bpf_pifo_rb(map);
	struct xdp_frame *frm;

	raw_spin_lock(&rb->lock);

	frm = xdp_rb_first(&rb->root);
	if (!frm)
		goto out;

	rb_erase(&frm->rbnode, &rb->root);
	*rank = frm->rank;
	rb->num_queued--;

out:
	raw_spin_unlock(&rb->lock);
	return frm;
}


static int pifo_rb_map_redirect(struct bpf_map *map, u64 index, u64 flags)
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



BTF_ID_LIST_SINGLE(pifo_rb_btf_ids, struct, bpf_pifo_rb)
const struct bpf_map_ops pifo_rb_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = pifo_rb_alloc_check,
	.map_alloc = pifo_rb_alloc,
	.map_free = pifo_rb_free,
	.map_lookup_elem_sys_only = pifo_rb_lookup_elem_sys,
	.map_lookup_elem = pifo_rb_lookup_elem,
	.map_update_elem = pifo_rb_update_elem,
	.map_delete_elem = pifo_rb_delete_elem,
	.map_get_next_key = pifo_rb_get_next_key,
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_pifo_rb,
	.map_btf_id = &pifo_rb_btf_ids[0],
	.map_redirect = pifo_rb_map_redirect,
};
