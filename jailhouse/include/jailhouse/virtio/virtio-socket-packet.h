#ifndef VIRTIO_SOCKET_PACKET_H
#define VIRTIO_SOCKET_PACKET_H

#if !defined(_JAILHOUSE_TYPES_H) && !defined(_JAILHOUSE_INMATE_H)
#error Needs prior include of <jailhouse/types.h> or <inmate.h>
#include <jailhouse/types.h>
#endif

#include <linux/virtio_vsock.h>
#include <linux/virtio_queue.h>

struct vsock_pkt_info {
	u8 receiver_cpu_id;
	u16 sender_buffer_id;
	u32 bytes_transfered; /* set to zero by client, updated by broker */
	u64 abs_deadline;
};

struct vsock_pkt {
	struct virtio_vsock_hdr *hdr;
	struct virtq_desc *tx_hdr_buf;
	struct vsock_pkt_info *info;
	u16 receiver_buffer_id;
};
#define VSOCK_PKT_PRINTF_FMT "%llu:%u -> %llu:%u - sz=%u op=%u"
#define VSOCK_PKT_PRINTF_FMT_VALS(p) (p)->hdr->src_cid, (p)->hdr->src_port, \
				     (p)->hdr->dst_cid, (p)->hdr->dst_port, \
				     (p)->hdr->len, (p)->hdr->op



/** Query if the packet contains a payload. */
static inline bool vsock_pkt_is_data_type(struct vsock_pkt *pkt)
{
	return pkt->hdr->op == VIRTIO_VSOCK_OP_RW;
}

/** Determine if the packet was transfered completely. */
static inline bool vsock_pkt_is_transfer_complete(struct vsock_pkt *pkt)
{
	return pkt->hdr->len == 0
	       || pkt->info->bytes_transfered == pkt->hdr->len;
}

static inline bool
virtio_socket_packet_is_control(struct vsock_pkt *pkt)
{
	return pkt->hdr->op == VIRTIO_VSOCK_OP_REQUEST
	       || pkt->hdr->op == VIRTIO_VSOCK_OP_RESPONSE
	       || pkt->hdr->op == VIRTIO_VSOCK_OP_RST
	       || pkt->hdr->op == VIRTIO_VSOCK_OP_SHUTDOWN;
}

static inline bool
virtio_socket_packet_is_credit(struct vsock_pkt *pkt)
{
	return pkt->hdr->op == VIRTIO_VSOCK_OP_CREDIT_UPDATE
	       || pkt->hdr->op == VIRTIO_VSOCK_OP_CREDIT_REQUEST;
}

#endif /* VIRTIO_SOCKET_PACKET_H */
