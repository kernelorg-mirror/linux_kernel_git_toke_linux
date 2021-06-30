// SPDX-License-Identifier: GPL-2.0-only

/* Pifomaps queue packets
 */
#include <linux/bpf.h>
#include <linux/bitops.h>
#include <net/xdp.h>
#include <linux/filter.h>
#include <trace/events/xdp.h>

#define PIFO_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY)

struct bpf_pifo_bucket {
	struct xdp_frame *head, *tail;
	u32 frame_count;
};

struct bpf_pifo_queue {
	struct bpf_pifo_bucket *buckets;
	unsigned long *bitmap;
	unsigned long **lvl_bitmap;
	u32 min_rank;
	u32 levels;
	u32 range;
};

struct bpf_pifo_map {
	struct bpf_map map;
	struct bpf_pifo_queue *queue;
	long num_queued;
};

static void pifo_queue_free(struct bpf_pifo_queue *q)
{
	bpf_map_area_free(q->buckets);
	bpf_map_area_free(q->bitmap);
	bpf_map_area_free(q->lvl_bitmap);
	kfree(q);
}

static struct bpf_pifo_queue *pifo_queue_alloc(u32 range, int numa_node)
{
	u32 num_longs = 0, offset = 0, i, lvl, levels;
	struct bpf_pifo_queue *q;

	levels = __KERNEL_DIV_ROUND_UP(ilog2(range), ilog2(BITS_PER_TYPE(long)));
	for (i = 0, lvl = 1; i < levels; i++) {
		num_longs += lvl;
		lvl *= BITS_PER_TYPE(long);
	}

	q = kzalloc(sizeof(struct bpf_pifo_queue), GFP_USER | __GFP_ACCOUNT);
	if (!q)
		return NULL;
	q->buckets = bpf_map_area_alloc(sizeof(struct bpf_pifo_bucket) * range,
					numa_node);
	if (!q->buckets)
		goto err;

	q->bitmap = bpf_map_area_alloc(sizeof(unsigned long) * num_longs,
				       numa_node);
	if (!q->bitmap)
		goto err;

	q->lvl_bitmap = bpf_map_area_alloc(sizeof(unsigned long *) * levels,
					   numa_node);
	for (i = 0, lvl = 1; i < levels; i++) {
		q->lvl_bitmap[i] = &q->bitmap[offset];
		offset += lvl;
		lvl *= BITS_PER_TYPE(long);
	}
	q->levels = levels;
	q->range = range;
	return q;


err:
	pifo_queue_free(q);
	return NULL;
}


static int pifo_map_init_map(struct bpf_pifo_map *pifo, union bpf_attr *attr)
{
	u32 range = attr->max_entries;

	/* check sanity of attributes. value size is the number of buckets,
	 * which must be at least 8
	 */
	if (attr->value_size != 4 || attr->key_size != 4 ||
	    !range || range < 8 || !is_power_of_2(range) ||
	    attr->map_flags & ~PIFO_CREATE_FLAG_MASK)
		return -EINVAL;

	/* PIFO map is special, we don't want BPF writing straight to it
	 */
	attr->map_flags |= BPF_F_RDONLY_PROG;
	bpf_map_init_from_attr(&pifo->map, attr);

	pifo->queue = pifo_queue_alloc(range, pifo->map.numa_node);
	if (!pifo->queue)
		return -ENOMEM;

	return 0;
}

static struct bpf_map *pifo_map_alloc(union bpf_attr *attr)
{
	struct bpf_pifo_map *pifo;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);

	pifo = kzalloc(sizeof(*pifo), GFP_USER | __GFP_ACCOUNT);
	if (!pifo)
		return ERR_PTR(-ENOMEM);

	err = pifo_map_init_map(pifo, attr);
	if (err) {
		kfree(pifo);
		return ERR_PTR(err);
	}

	return &pifo->map;
}

static void pifo_queue_flush(struct bpf_pifo_queue *queue)
{
	unsigned long *bitmap = queue->lvl_bitmap[queue->levels - 1];
	int i = 0;

	while (i < queue->range) {
		struct bpf_pifo_bucket *bucket = &queue->buckets[i];
		struct xdp_frame *frame = bucket->head, *next;

		while(frame) {
			next = frame->next;
			xdp_return_frame(frame);
			frame = next;
		}
		i = find_next_bit(bitmap, queue->range, i + 1);
	}
}

static void pifo_map_free(struct bpf_map *map)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);

	/* At this point bpf_prog->aux->refcnt == 0 and this map->refcnt == 0,
	 * so the programs (can be more than one that used this map) were
	 * disconnected from events. The following synchronize_rcu() guarantees
	 * both rcu read critical sections complete and waits for
	 * preempt-disable regions (NAPI being the relevant context here) so we
	 * are certain there will be no further reads against the netdev_map and
	 * all flush operations are complete. Flush operations can only be done
	 * from NAPI context for this reason.
	 */

	synchronize_rcu();

	/* Make sure prior __dev_map_entry_free() have completed. */
	rcu_barrier();

	pifo_queue_flush(pifo->queue);
	pifo_queue_free(pifo->queue);
	kfree(pifo);
}

static int pifo_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	u32 index = key ? *(u32 *)key : U32_MAX, offset;
	struct bpf_pifo_queue *queue = pifo->queue;
	u32 *next = next_key;
	unsigned long idx;


	if (index == U32_MAX || index < queue->min_rank)
		offset = queue->min_rank;
	else
		offset = index - queue->min_rank + 1;

	if (offset >= queue->range)
		return -ENOENT;

	idx = find_next_bit(queue->lvl_bitmap[queue->levels - 1],
			    queue->range, offset);
	if (idx == queue->range)
		return -ENOENT;

	*next = idx;
	return 0;
}

static void pifo_set_bit(struct bpf_pifo_queue *queue, u32 rank)
{
	u32 i;

	for (i = queue->levels; i > 0; i--) {
		unsigned long *bitmap = queue->lvl_bitmap[i-1];
		set_bit(rank, bitmap);
		rank /= BITS_PER_TYPE(long);
	}
}

static void pifo_clear_bit(struct bpf_pifo_queue *queue, u32 rank)
{
	u32 i;

	for (i = queue->levels; i > 0; i--) {
		unsigned long *bitmap = queue->lvl_bitmap[i-1];
		clear_bit(rank, bitmap);
		rank /= BITS_PER_TYPE(long);

		// another bit is set in this word, don't clear bit in higher
		// level
		if (*(bitmap + rank))
			break;
	}
}

int pifo_map_enqueue(struct bpf_map *map, struct xdp_frame *xdpf, u32 index)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	struct bpf_pifo_queue *queue = pifo->queue;
	struct bpf_pifo_bucket *bucket;
	u32 q_index;

	if (unlikely(pifo->num_queued >= pifo->map.max_entries))
		return -EOVERFLOW;

	xdpf->next = NULL;

	q_index = index - min(queue->min_rank, index);
	if (unlikely(q_index >= queue->range))
		q_index = queue->range - 1;

	bucket = &queue->buckets[q_index];
	if (likely(!bucket->tail)) {
		bucket->head = bucket->tail = xdpf;
		pifo_set_bit(queue, q_index);
	} else {
		bucket->tail->next = xdpf;
		bucket->tail = xdpf;
	}

	pifo->num_queued++;
	bucket->frame_count++;
	return 0;
}

static unsigned long pifo_find_first_bucket(struct bpf_pifo_queue *queue)
{
	unsigned long *bitmap, bit = 0, offset;
	int i;

	for (i = 0; i < queue->levels; i++) {
		bitmap = queue->lvl_bitmap[i] + bit;
		if (!*bitmap)
			return -1;
		offset = bit;
		bit = __ffs(*bitmap);
	}
	return offset * BITS_PER_TYPE(long) + bit;
}

struct xdp_frame *pifo_map_dequeue(struct bpf_map *map, u64 flags)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	struct bpf_pifo_queue *queue = pifo->queue;
	struct bpf_pifo_bucket *bucket;
	unsigned long bucket_idx;
	struct xdp_frame *xdpf;

	/* FIXME: How to return an error different from NULL here? */
	if (flags)
		return NULL;

	bucket_idx = pifo_find_first_bucket(queue);
	if (bucket_idx == -1)
		return NULL;
	bucket = &queue->buckets[bucket_idx];

	if (WARN_ON_ONCE(!bucket->tail))
		return NULL;

	xdpf = bucket->head;
	if (likely(xdpf->next)) {
		bucket->head = xdpf->next;
	} else {
		bucket->tail = NULL;
		pifo_clear_bit(queue, bucket_idx);
	}
	pifo->num_queued--;
	bucket->frame_count--;
	return xdpf;
}

static void *pifo_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	struct bpf_pifo_queue *queue = pifo->queue;
	struct bpf_pifo_bucket *bucket;
	u32 rank =  *(u32 *)key, idx;

	if (rank < queue->min_rank)
		return NULL;

	idx = rank - queue->min_rank;
	if (idx >= queue->range)
		return NULL;

	bucket = &queue->buckets[idx];
	return &bucket->frame_count;
}

static int pifo_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	return -EINVAL;
}

static int pifo_map_redirect(struct bpf_map *map, u32 index, u64 flags)
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

static int pifo_map_btf_id;
const struct bpf_map_ops pifo_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = pifo_map_alloc,
	.map_free = pifo_map_free,
	.map_get_next_key = pifo_map_get_next_key,
	.map_lookup_elem = pifo_map_lookup_elem,
	.map_update_elem = pifo_map_update_elem,
	.map_check_btf = map_check_no_btf,
	.map_btf_name = "bpf_pifo_map",
	.map_btf_id = &pifo_map_btf_id,
	.map_redirect = pifo_map_redirect,
};
