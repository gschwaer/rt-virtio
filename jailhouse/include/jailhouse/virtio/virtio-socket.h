#ifndef VIRTIO_SOCKET_H
#define VIRTIO_SOCKET_H

/* Either include
 * #include <jailhouse/types.h> // for jailhouse internal code
 * or
 * #include <inmate.h> // for inmate code
 * before including this header.
 */
#if defined(_JAILHOUSE_TYPES_H) //#include <jailhouse/types.h>
#include <jailhouse/assert.h>
#include <jailhouse/string.h>
#include <jailhouse/utils.h>
#elif defined(_JAILHOUSE_INMATE_H) //#include <inmate.h>
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#else
#error Needs prior include of <jailhouse/types.h> or <inmate.h>
#include <jailhouse/types.h>
#include <jailhouse/assert.h>
#include <jailhouse/string.h>
#include <jailhouse/utils.h>
#include <asm/processor.h>
#endif

#include <jailhouse/cell-config.h>
#include <jailhouse/virtio/virtqueue.h>
#include <jailhouse/virtio/virtio-socket-packet.h>


/* As specified in virtio spec ch 5.10.2 */
#define VSOCK_NUM_QUEUES		3
/* As specified in virtio spec ch 2.6 */
#define VSOCK_CID_HOST			2


struct virtq_cfg {
	//TODO make the following to unsigned long (?)
        struct virtq_desc *desc;
        struct virtq_avail *avail;
        struct virtq_used *used;
        u16 num;
	u16 enabled;
};

struct rtvsock_info { // TODO maybe rename to just vsock_info since this is quite generic
	union {
		struct {
			struct virtq_cfg rx;
			struct virtq_cfg tx;
			struct virtq_cfg event;
		} virtq_cfg;
		struct virtq_cfg virtq_cfgs[VSOCK_NUM_QUEUES];
	};
	struct jailhouse_memory virtqs_src_as;
	struct jailhouse_memory virtqs_dst_as;
	u64 guest_cid;
	u8 cpu_id;
};

struct rtvsock { // TODO maybe rename to just vsock since this is quite generic
	union {
		struct {
			struct virtqueue rx;
			struct virtqueue tx;
			struct virtqueue event;
		} virtq;
		struct virtqueue virtqs[VSOCK_NUM_QUEUES];
	};
	struct rtvsock_info *info; /* points to shared data */
};


static inline bool
lin_phys_range_equal(const struct jailhouse_memory *restrict mem1,
		     const struct jailhouse_memory *restrict mem2)
{
	return mem1->phys_start == mem2->phys_start
	       && mem1->size == mem2->size
	       && mem1->colors == mem2->colors;
}
/* Convert address between different mappings assuming linear mapping (offset
 * based). */
static inline void *
lin_virt2virt(void *addr, const struct jailhouse_memory *restrict src_mem,
	      const struct jailhouse_memory *restrict dst_mem)
{
	assert(((u64)addr >= src_mem->virt_start)
	       && ((u64)addr < (src_mem->virt_start + src_mem->size))
	       && lin_phys_range_equal(src_mem, dst_mem));
	return addr - src_mem->virt_start + dst_mem->virt_start;
}
static inline void *lin_virt2phys(void *addr,
				  const struct jailhouse_memory *mem)
{
	assert(((u64)addr >= mem->virt_start)
	       && ((u64)addr < (mem->virt_start + mem->size)));
	return addr - mem->virt_start + mem->phys_start;
}
static inline void *lin_phys2virt(void *addr,
				  const struct jailhouse_memory *mem)
{
	assert(((u64)addr >= mem->phys_start)
	       && ((u64)addr < (mem->phys_start + mem->size)));
	return addr - mem->phys_start + mem->virt_start;
}


/** defined by application
 *  Should inform the two specified cores of a packet event. */
//TODO this' ugly
extern void notify_two_cores(u64 core_id_1, u64 core_id_2);

static inline bool vsock_fetch_packet_info(struct rtvsock *rtvsock,
					   struct vsock_pkt_info *pkt_info)
{
	pkt_info->receiver_cpu_id = 0;
	pkt_info->bytes_transfered = 0;
	pkt_info->abs_deadline = 0;
	return virtqueue_get_avail_buffer(&rtvsock->virtq.tx,
					  &pkt_info->sender_buffer_id) != NULL;
}

/** Fetch the header of a pending packet of {socket} and populate the following
 *  fields in the {packet} with it:
 *  - hdr
 *  - tx_hdr_buf
 *  - sender_buffer_id
 *  Returns true if a header buffer was obtained, false otherwise. */
static inline bool vsock_fetch_packet_header(struct rtvsock *rtvsock,
					     struct vsock_pkt *packet)
{
	void *virt;

	packet->tx_hdr_buf = virtqueue_get_avail_buffer(&rtvsock->virtq.tx,
						&packet->info->sender_buffer_id);
	if (!packet->tx_hdr_buf) {
		/* no new buffer available */
		return false;
	}

	/* header buffer should be read-only */
	assert(virtqueue_buffer_is_read_only(packet->tx_hdr_buf));
	/* buffer is not a header buffer */
	assert(packet->tx_hdr_buf->len == sizeof(*packet->hdr));

	virt = lin_virt2virt((void*)packet->tx_hdr_buf->addr,
			      &rtvsock->info->virtqs_src_as,
			      &rtvsock->info->virtqs_dst_as);
	packet->hdr = (struct virtio_vsock_hdr*)virt;

	/* no specified packets for this destination */
	assert(packet->hdr->dst_cid != VSOCK_CID_HOST);

	return true;
}

static inline bool
vsock_notify_transfer(struct rtvsock *rtvsock_sender,
		      struct rtvsock *rtvsock_receiver,
		      struct vsock_pkt *packet, u32 bytes_sent)
{
	bool transfer_complete = false;
	u64 cpu_id_snd;

	virtqueue_put_used_buf(&rtvsock_receiver->virtq.rx,
			       packet->receiver_buffer_id,
			       bytes_sent + sizeof(struct virtio_vsock_hdr));
	if (vsock_pkt_is_transfer_complete(packet)) {
		/* no data or we transmitted all the data, so we don't need the
		 * TX buffer anymore nad can return it */
		virtqueue_put_used_buf(&rtvsock_sender->virtq.tx,
				       packet->info->sender_buffer_id, 0);
		transfer_complete = true;
		cpu_id_snd = rtvsock_sender->info->cpu_id;
	} else {
		/* don't notify the sender */
		cpu_id_snd = (u64)-1;
	}
	/* make changes to the virtqueues visible before notifying */
	memory_barrier();

	notify_two_cores(cpu_id_snd, rtvsock_receiver->info->cpu_id);

	return transfer_complete;
}

/** Send a reset packet to the {rtvsock} of a received {packet}. Returns true if
 *  packet was successfully sent, and false otherwise. */
static inline bool vsock_send_reset(struct rtvsock *rtvsock,
				    struct vsock_pkt *packet)
{
        struct virtq_desc *hdr_buf_receiver;
        struct virtio_vsock_hdr *hdr_sender = packet->hdr;
        struct virtio_vsock_hdr *hdr_receiver;
        void *virt;

        hdr_buf_receiver = virtqueue_get_avail_buffer(&rtvsock->virtq.rx,
					&packet->receiver_buffer_id);
        if (!hdr_buf_receiver) {
                /* no RX buffer available */
                return false;
        }
        assert(!virtqueue_buffer_is_read_only(hdr_buf_receiver));
        assert(hdr_buf_receiver->len == sizeof(*hdr_receiver));

        virt = lin_virt2virt((void*)hdr_buf_receiver->addr,
			     &rtvsock->info->virtqs_src_as,
			     &rtvsock->info->virtqs_dst_as);
        hdr_receiver = (struct virtio_vsock_hdr *)virt;

        /* write reset header */
        hdr_receiver->src_cid = VSOCK_CID_HOST;
        hdr_receiver->dst_cid = hdr_sender->src_cid;
        hdr_receiver->src_port = hdr_sender->dst_port;
        hdr_receiver->dst_port = hdr_sender->src_port;
        hdr_receiver->len = 0;
        hdr_receiver->type = VIRTIO_VSOCK_TYPE_STREAM;
        hdr_receiver->op = VIRTIO_VSOCK_OP_RST;
        hdr_receiver->flags = 0;
        hdr_receiver->buf_alloc = 0;
        hdr_receiver->fwd_cnt = 0;

        return vsock_notify_transfer(rtvsock, rtvsock, packet, 0);
}

/** Query if the given {socket} has a packet pending. */
static inline bool vsock_pkt_pending(struct rtvsock *rtvsock)
{
	return virtqueue_avail_has_buf(&rtvsock->virtq.tx);
}

/** Prepare transfer of {packet}, by fetching a buffer on {receiver_socket} side
 *  and providing pointers to {sender_data} and {receiver_data}, that can be
 *  used for copying. Returns false if {receiver_socket} has no buffers
 *  available, true otherwise. */
static inline bool vsock_pkt_prepare_send(struct vsock_pkt *packet,
					  struct rtvsock *socket_sender,
					  struct rtvsock *socket_receiver,
					  void **data_sender,
					  void **data_receiver,
					  u32 *bytes_sent)
{
	struct virtq_desc *hdr_buf_sender, *data_buf_sender,
			  *hdr_buf_receiver, *data_buf_receiver;
	struct virtio_vsock_hdr *hdr_sender, *hdr_receiver;
	void *virt;

	/* setup header buffers */
	hdr_buf_sender = packet->tx_hdr_buf;
	hdr_sender = packet->hdr;
	hdr_buf_receiver = virtqueue_get_avail_buffer(
				   &socket_receiver->virtq.rx,
				   &packet->receiver_buffer_id);
	if (!hdr_buf_receiver) {
		/* no RX buffer available */
		return false;
	}
	assert(!virtqueue_buffer_is_read_only(hdr_buf_receiver));
	assert(hdr_buf_receiver->len == sizeof(*hdr_receiver));

	virt = lin_virt2virt((void*)hdr_buf_receiver->addr,
			      &socket_receiver->info->virtqs_src_as,
			      &socket_receiver->info->virtqs_dst_as);
	hdr_receiver = (struct virtio_vsock_hdr*)virt;

	/* copy header data */
	memcpy(hdr_receiver, hdr_sender, sizeof(*hdr_receiver));

	if (hdr_sender->len > 0) {
		/* setup data buffers */
		data_buf_sender = virtqueue_get_next(&socket_sender->virtq.tx,
						     hdr_buf_sender);
		assert(data_buf_sender);

		virt = lin_virt2virt((void*)data_buf_sender->addr,
				     &socket_sender->info->virtqs_src_as,
				     &socket_sender->info->virtqs_dst_as);
		*data_sender = virt + packet->info->bytes_transfered;

		data_buf_receiver = virtqueue_get_next(
					    &socket_receiver->virtq.rx,
					    hdr_buf_receiver);
		assert(data_buf_receiver);
		assert(!virtqueue_buffer_is_read_only(data_buf_receiver));

		virt = lin_virt2virt((void*)data_buf_receiver->addr,
				     &socket_receiver->info->virtqs_src_as,
				     &socket_receiver->info->virtqs_dst_as);
		*data_receiver = virt;

		/* setup data copy */
		*bytes_sent = MIN(data_buf_sender->len
				  - packet->info->bytes_transfered,
				  data_buf_receiver->len);
		hdr_receiver->len = *bytes_sent;

		assert(hdr_sender->len == data_buf_sender->len);
		assert(!virtqueue_get_next(&socket_sender->virtq.tx,
					   data_buf_sender));
		assert(!virtqueue_get_next(&socket_receiver->virtq.rx,
					   data_buf_receiver));
	} else {
		*bytes_sent = 0;
	}

	return true;
}

static inline void vsock_get_pkt_from_info(struct vsock_pkt *pkt,
					   struct vsock_pkt_info *info,
					   struct rtvsock *vsock)
{
	pkt->info = info;
	pkt->tx_hdr_buf = virtqueue_get_buf_by_id(&vsock->virtq.tx,
						  info->sender_buffer_id);
	pkt->hdr = lin_virt2virt((void*)pkt->tx_hdr_buf->addr,
				 &vsock->info->virtqs_src_as,
				 &vsock->info->virtqs_dst_as);
}

/* Notes:
 * - There are some erroneous conditions that may arise, which wo do not have to
 *   care about, since the receiver will complain to the sender about it. E.g.:
 *   - packet->hdr->type != VIRTIO_VSOCK_TYPE_STREAM
 *   - packet->hdr->len < buf->len
 *   - packet->hdr->op == VIRTIO_VSOCK_OP_INVALID
 * - Right now we only support the split buffer approach, where one buffer
 *   contains the header and the <next> buffer contains the data.
 * - Connection Procedure (spec 5.10.6.5):
 *   - G1->G2:  VIRTIO_VSOCK_OP_REQUEST (open connection)
 *   - G2->G1:  VIRTIO_VSOCK_OP_RESPONSE (ack) / VIRTIO_VSOCK_OP_RST (nack)
 *   - G1<->G2: VIRTIO_VSOCK_OP_RW (...)
 *   - Gx->Gy:  VIRTIO_VSOCK_OP_SHUTDOWN(close connection, flags 0b01 = no recv,
 *	        0b10 = no send)
 *   - Gy->Gx:  VIRTIO_VSOCK_OP_RST (connection closed) (if missing, after
 *              timeout Gx->Gy: VIRTIO_VSOCK_OP_RST)
 */

#endif // VIRTIOSOCKET_H
