#ifndef VIRTQUEUE_H
#define VIRTQUEUE_H

/* Either include
 * #include <jailhouse/types.h> // for jailhouse internal code
 * or
 * #include <inmate.h> // for inmate code
 * before including this header.
 */
#if defined(_JAILHOUSE_TYPES_H) //#include <jailhouse/types.h>
#include <jailhouse/assert.h>
#include <jailhouse/printk.h>
#include <asm/processor.h>
#elif defined(_JAILHOUSE_INMATE_H) //#include <inmate.h>
#else
#error Needs prior include of <jailhouse/types.h> or <inmate.h>
#include <jailhouse/types.h>
#include <jailhouse/assert.h>
#include <jailhouse/printk.h>
#include <asm/processor.h>
#endif

#include <linux/virtio_queue.h>

struct virtqueue {
        volatile struct virtq_desc *desc;
        volatile struct virtq_avail *avail;
        volatile struct virtq_used *used;
        u16 num;
	u16 enabled;
	/* the naming is bad, it actually means the last id the driver used and
	 * the device saw + 1, but it seems to be some sort of convention (see
	 * virtio spec) */
	u16 avail_ring_last_seen_idx;
	u16 used_ring_last_seen_idx;
	u16 free_desc_stack_top;
	u16 num_free_desc;
};

static inline void virtqueue_initialize_desc_tbl(struct virtqueue *vqueue)
{
	u32 i;
	for (i = 0; i < vqueue->num; ++i) {
		vqueue->desc[i].next = (u16)((i+1) % vqueue->num);
	}
	vqueue->num_free_desc = (u16)vqueue->num;
}

static inline struct virtq_desc *
virtqueue_get_buf_by_id(struct virtqueue *vqueue, u16 buf_id)
{
	return (struct virtq_desc*)&vqueue->desc[buf_id];
}

static inline void
virtqueue_disable_avail_notifications(struct virtqueue *vqueue)
{
	vqueue->avail->flags |= VIRTQ_AVAIL_F_NO_INTERRUPT;
}

static inline void
virtqueue_disable_used_notifications(struct virtqueue *vqueue)
{
	vqueue->used->flags |= VIRTQ_USED_F_NO_NOTIFY;
}

static inline bool virtqueue_avail_has_buf(struct virtqueue *vqueue)
{
	return vqueue->avail->idx != vqueue->avail_ring_last_seen_idx;
}

static inline bool virtqueue_used_has_buf(struct virtqueue *volatile vqueue)
{
	return vqueue->used->idx != vqueue->used_ring_last_seen_idx;
}

static inline u16 virtqueue_get_avail_buf_id(struct virtqueue *vqueue)
{
	u16 buf_id;

	assert(virtqueue_avail_has_buf(vqueue));

	buf_id = vqueue->avail->ring[vqueue->avail_ring_last_seen_idx
				     % vqueue->num];
	vqueue->avail_ring_last_seen_idx++;

	return buf_id;
}

static inline struct virtq_used_elem *
virtqueue_get_used_buf_elem(struct virtqueue *vqueue)
{
	volatile struct virtq_used_elem *buf_elem;

	assert(virtqueue_used_has_buf(vqueue));

	buf_elem = &vqueue->used->ring[vqueue->used_ring_last_seen_idx
				       % vqueue->num];
	vqueue->used_ring_last_seen_idx++;

	return (struct virtq_used_elem*)buf_elem;
}

static inline void virtqueue_put_used_buf(struct virtqueue *vqueue, u16 buf_id,
					  u32 used_length)
{
	volatile struct virtq_used_elem *used_elem;

	used_elem = &vqueue->used->ring[vqueue->used->idx
				        % vqueue->num];
	used_elem->id = buf_id;
	used_elem->len = used_length;

	/* persist changes to the buffer element before making it visible */
	memory_barrier();

	vqueue->used->idx++;
}

static inline void virtqueue_put_avail_buf(struct virtqueue *vqueue, u16 buf_id)
{
	vqueue->avail->ring[vqueue->avail->idx % vqueue->num] = buf_id;

	/* No memory barrier required, since this function is only used by the
	 * client OS driver. The memory barrier is performed at the hypervisor
	 * level for this case. */
	vqueue->avail->idx++;
}

static inline bool virtqueue_has_free_buf(struct virtqueue *vqueue)
{
	return vqueue->num_free_desc != 0;
}

static inline u16 virtqueue_get_free_buf_id(struct virtqueue *vqueue)
{
	u16 free_buf_id;

	assert(virtqueue_has_free_buf(vqueue));

	free_buf_id = vqueue->free_desc_stack_top;
	vqueue->free_desc_stack_top =
			virtqueue_get_buf_by_id(vqueue, free_buf_id)->next;
	vqueue->num_free_desc--;

	return free_buf_id;
}

static inline void virtqueue_put_free_buf(struct virtqueue *vqueue, u16 buf_id)
{
	assert(vqueue->num_free_desc != vqueue->num);

	virtqueue_get_buf_by_id(vqueue, buf_id)->next =
			vqueue->free_desc_stack_top;
	vqueue->free_desc_stack_top = buf_id;
	vqueue->num_free_desc++;
}

static inline void virtqueue_buffer_set_data(struct virtq_desc *buffer,
					     u64 addr, u32 len)
{
	buffer->addr = addr;
	buffer->len = len;
}

static inline void virtqueue_buffer_init(struct virtq_desc *buffer, u64 addr,
					 u32 len)
{
	virtqueue_buffer_set_data(buffer, addr, len);
	buffer->flags = 0;
	buffer->next = 0;
}

static inline void virtqueue_buffer_set_read_only(struct virtq_desc *buffer)
{
	buffer->flags &= ~VIRTQ_DESC_F_WRITE;
}

static inline void virtqueue_buffer_set_read_write(struct virtq_desc *buffer)
{
	buffer->flags |= VIRTQ_DESC_F_WRITE;
}

static inline bool virtqueue_buffer_is_read_only(struct virtq_desc *buffer)
{
	return !(buffer->flags & VIRTQ_DESC_F_WRITE);
}

static inline void virtqueue_buffer_set_next(struct virtq_desc *buffer,
				      u16 next_buf_id)
{
	buffer->next = next_buf_id;
	buffer->flags |= VIRTQ_DESC_F_NEXT;
}

static inline bool virtqueue_buffer_has_next(struct virtq_desc *buffer)
{
	return buffer->flags & VIRTQ_DESC_F_NEXT;
}

static inline u16 virtqueue_buffer_get_next_buf_id(struct virtq_desc *buffer)
{
	return buffer->next;
}

static inline struct virtq_desc *
virtqueue_get_avail_buffer(struct virtqueue *vqueue, u16 *buffer_id)
{
	volatile struct virtq_desc *buffer;

	if (!virtqueue_avail_has_buf(vqueue))
		return NULL;

	*buffer_id = vqueue->avail->ring[vqueue->avail_ring_last_seen_idx
					 % vqueue->num];
	buffer = &vqueue->desc[*buffer_id];

	vqueue->avail_ring_last_seen_idx++;

	return (struct virtq_desc*)buffer;
}

static inline struct virtq_desc *virtqueue_get_next(struct virtqueue *vqueue,
						    struct virtq_desc *buffer)
{
	u16 buffer_id;
	volatile struct virtq_desc *next_buffer;

	if (!(buffer->flags & VIRTQ_DESC_F_NEXT))
		return NULL;

	buffer_id = buffer->next;
	next_buffer = &vqueue->desc[buffer_id];

	return (struct virtq_desc*)next_buffer;
}

static inline void virtqueue_dump(struct virtqueue *vqueue)
{
	unsigned int i;

	if (vqueue == NULL) {
		printk("virtqueue is NULL\n");
		return;
	}

	printk("\t- avail_ring_last_seen_idx = 0x%x\n",
	       vqueue->avail_ring_last_seen_idx);
	printk("\t- used_ring_last_seen_idx = 0x%x\n",
	       vqueue->used_ring_last_seen_idx);
	printk("\t- free_desc_stack_top = 0x%x\n",
	       vqueue->free_desc_stack_top);
	printk("\t- num_free_desc = 0x%x\n",
	       vqueue->num_free_desc);
	printk("\t- vring.num = 0x%x\n", vqueue->num);

	if (vqueue->desc == NULL) {
		printk("\t- vring.desc is NULL\n");
	} else if (vqueue->num == 0) {
		printk("\t- descriptor table: None\n");
	} else {
		printk("\t- descriptor table:\n");
		for (i = 0; i < vqueue->num; ++i) {
			printk("\t\t[%u] addr=0x%08llx, len=0x%08x, "
			       "flags=0x%04x, next=0x%04x\n", i,
			       vqueue->desc[i].addr,
			       vqueue->desc[i].len,
			       vqueue->desc[i].flags,
			       vqueue->desc[i].next);
		}
	}

	if (vqueue->avail == NULL) {
		printk("\t- vring.avail is NULL\n");
	} else if (vqueue->num == 0) {
		printk("\t- available/driver ring: idx=0x%04x, flags=0x%04x, "
		       "ring=None\n", vqueue->avail->idx,
		       vqueue->avail->flags);
	} else {
		printk("\t- available/driver ring: idx=0x%04x, flags=0x%04x\n",
		       vqueue->avail->idx, vqueue->avail->flags);
		for (i = 0; i < vqueue->num; ++i) {
			printk("\t\t[%u] id=0x%04x\n", i,
			       vqueue->avail->ring[i]);
		}
	}

	if (vqueue->used == NULL) {
		printk("\t- vring.used is NULL\n");
	} else if (vqueue->num == 0) {
		printk("\t- used/device ring: idx=0x%04x, flags=0x%04x, "
		       "ring=None\n", vqueue->used->idx,
		       vqueue->used->flags);
	} else {
		printk("\t- used/device ring: idx=0x%04x, flags=0x%04x\n",
		       vqueue->used->idx,
		       vqueue->used->flags);
		for (i = 0; i < vqueue->num; ++i) {
			printk("\t\t[%u] id=0x%04x, len=0x%08x\n", i,
			       vqueue->used->ring[i].id,
			       vqueue->used->ring[i].len);
		}
	}
}

#endif /* VIRTQUEUE_H */
