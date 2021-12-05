#include <inmate.h>

#include <jailhouse/virtio/virtio-socket.h>
#include <jailhouse/virtio/virtqueue.h>

#include <linux/pci_ids.h>
#include <linux/pci_regs.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_config.h>
#include <linux/virtio_vsock.h>

#include "virtio-socket-driver.h"

#define MAX_NUM_SOCKETS 2

/**
 * The implementation has some limitations:
 * 1. only MAX_NUM_SOCKETS sockets, i.e. only MAX_NUM_SOCKETS bidirectional
 *    connections to a peer
 * 2. no support for multiple connections to the same inbound port, e.g.
 *    (a:x -> c:y), (b:z -> c:y) is not supported.
 * 3. the virtio standard assumes that the recevier will buffer packets, up to
 *    buf_alloc size, which we don't
 * 4. we assume sending of control messages to succeed, but the tx ring buffer
 *    could be full. Currently we assert this (marked: queueing limitation).
 * 5. we don't support the event queue (vsock implementation in jailhouse does
 *    not either).
 *
 * Limitation 1 can be solved by implementing a list structure for the sockets.
 */


#define RX_PACKET_SIZE				4096
#define BUFFER_SPACE_MGMT_BUF_ALLOC		(1024*1024)

#define VIRTIO_PCI_VENDOR_ID			PCI_VENDOR_ID_REDHAT_QUMRANET
#define VIRTIO_PCI_DEVICE_ID_VSOCK		(0x1040 + VIRTIO_ID_VSOCK)
/* This must not be mapped in cell config, but will be mapped in inmate, so
 * accesses trap to EL2 sync abort. */
#define BAR0_ADDR				0xF0000000ULL

#ifndef DEBUG
#define DEBUG  0
#endif

#define PRINTK_PREFIX "vsock-dri"
#define vsd_err(...) printk(PRINTK_PREFIX " (error): " __VA_ARGS__)
#define vsd_warn(...) printk(PRINTK_PREFIX " (warn ): " __VA_ARGS__)
#if DEBUG >= 1
#define vsd_info(...) printk(PRINTK_PREFIX " (info ): " __VA_ARGS__)
#else
#define vsd_info(...)
#endif
#if DEBUG >= 2
#define vsd_dbg(...) printk(PRINTK_PREFIX " (debug): " __VA_ARGS__)
#else
#define vsd_dbg(...)
#endif

#define VIRTIO_CONFIG_S_ALL_GOOD	(VIRTIO_CONFIG_S_ACKNOWLEDGE | \
					 VIRTIO_CONFIG_S_DRIVER | \
					 VIRTIO_CONFIG_S_FEATURES_OK | \
					 VIRTIO_CONFIG_S_DRIVER_OK)
/* Feature bits as in spec ch. 5.10: */
#define VIRTIO_SOCKET_FEATURE_BITS	(((u64)1) << VIRTIO_F_VERSION_1)
#define VIRTIO_SOCKET_FEATURE_BITS_LO	(((u32)VIRTIO_SOCKET_FEATURE_BITS) & 0xFFFFFFFF)
#define VIRTIO_SOCKET_FEATURE_BITS_HI	((u32)(VIRTIO_SOCKET_FEATURE_BITS >> 32))

struct vsock_socket;
static void add_empty_packet_to_virtqueue(struct virtqueue *vq);
static struct vsock_pkt2 *vsock_dri_get_packet(u32 pkt_id);
static inline void vsock_dri_notify(struct virtqueue *vq);
static int vsock_sock_send_ctrl_packet(struct vsock_socket *sock,
				       enum virtio_vsock_op op);
static int vsock_dri_send_ctrl_packet(u64 dst_cid, u32 dst_port, u32 src_port,
				      enum virtio_vsock_op op, u32 fwd_cnt);
static int vsock_dri_reset_sender(struct vsock_pkt2 *pkt);
static struct vsock_socket *get_socket_by_fd(s64 fd);
static struct vsock_socket *get_socket_by_port(u32 port);
static int add_socket(s64 *sock);

struct vsock_pkt2 {
	struct virtio_vsock_hdr hdr;
	struct virtq_desc *hdr_buf;
	struct virtq_desc *payload_buf;
	u16 hdr_buf_id;
	u16 payload_buf_id;
};

bool vsock_pkt_is_data_pkt(u32 pkt_id)
{
	return vsock_dri_get_packet(pkt_id)->hdr.op == VIRTIO_VSOCK_OP_RW;
}
u32 vsock_pkt_payload_size(u32 pkt_id)
{
	return vsock_dri_get_packet(pkt_id)->hdr.len;
}
void *vsock_pkt_payload(u32 pkt_id)
{
	if (!vsock_dri_get_packet(pkt_id)->payload_buf)
		return NULL;
	return (void*)vsock_dri_get_packet(pkt_id)->payload_buf->addr;
}

struct vsock_socket {
	pkt_event_handler rx_handler;
	void *rx_handler_param;
	u64 peer_cid;
	u32 peer_port;
	u32 sock_port;
	u32 buf_alloc;
	u32 fwd_cnt;
	enum conn_status_enum {
		CONN_STATUS_OUT_REQUESTED,
		CONN_STATUS_OUT_FAILED,
		CONN_STATUS_OUT_CONNECTED,
		CONN_STATUS_OUT_SHUTDOWN,
		CONN_STATUS_OUT_DISCONNECTED,
		CONN_STATUS_IN_OPEN,
		CONN_STATUS_IN_CONNECTED,
		CONN_STATUS_IN_DISCONNECTED,
	} conn_status;
};

static struct virtio_vsock_dev_pci {
	union {
		struct {
			struct virtqueue rx;
			struct virtqueue tx;
			struct virtqueue event;
		} vqueue;
		struct virtqueue vqueues[3];
	};
	volatile struct virtio_pci_common_cfg *cmn_cfg;
	volatile u8 *isr;
	volatile u16 *notify;
	struct vsock_pkt2 *rx_pkt_buffer;
	struct vsock_pkt2 *tx_pkt_buffer;
	struct vsock_socket *sockets[MAX_NUM_SOCKETS];
	pkt_event_handler tx_handler;
	void *tx_handler_param;
	u16 bdf;
	u8 irq_id;
	u64 cid;
} *vsock_dev;

#define PKT_ID_BUF_RX		(1 << 16)
#define PKT_ID_BUF_TX		(1 << 17)
#define PKT_ID_OFF_MASK		((1 << 16) - 1)

static u32 vsock_dri_generate_packet_id(struct virtqueue *vq, u16 buf_id)
{
	if (vq == &vsock_dev->vqueue.rx) {
		return (buf_id % vq->num) | PKT_ID_BUF_RX;
	} else if (vq == &vsock_dev->vqueue.tx) {
		return (buf_id % vq->num) | PKT_ID_BUF_TX;
	}
	assert(false);
	return 0;
}

static struct vsock_pkt2 *vsock_dri_get_packet(u32 pkt_handle)
{
	u16 pkt_id = pkt_handle & PKT_ID_OFF_MASK;

	assert(pkt_id < vsock_dri_queue_size());

	if (pkt_handle & PKT_ID_BUF_RX) {
		return &vsock_dev->rx_pkt_buffer[pkt_id];
	} else if (pkt_handle & PKT_ID_BUF_TX) {
		return &vsock_dev->tx_pkt_buffer[pkt_id];
	}
	assert(false);
	return NULL;
}

enum has_payload_enum {
	NO_PAYLOAD = 0,
	HAS_PAYLOAD
};
static int prepare_packet_for_sending(u32 *pkt_id,
				      enum has_payload_enum has_payload)
{
	struct virtqueue *tx_vq = &vsock_dev->vqueue.tx;
	struct vsock_pkt2 *pkt;
	u16 buf_id;

	vsd_dbg("Preparing tx packet\n");

	if (!virtqueue_has_free_buf(tx_vq)) {
		return -1;
	}
	buf_id = virtqueue_get_free_buf_id(tx_vq);
	*pkt_id = vsock_dri_generate_packet_id(tx_vq, buf_id);
	pkt = vsock_dri_get_packet(*pkt_id);

	pkt->hdr_buf_id = buf_id;
	pkt->hdr_buf = virtqueue_get_buf_by_id(tx_vq, pkt->hdr_buf_id);
	virtqueue_buffer_init(pkt->hdr_buf, (u64)&pkt->hdr, sizeof(pkt->hdr));
	virtqueue_buffer_set_read_only(pkt->hdr_buf);

	memset(&pkt->hdr, 0, sizeof(pkt->hdr));
	pkt->hdr.src_cid = vsock_dev->cid;
	pkt->hdr.len = 0;
	pkt->hdr.type = VIRTIO_VSOCK_TYPE_STREAM;
	pkt->hdr.buf_alloc = BUFFER_SPACE_MGMT_BUF_ALLOC;

	if (has_payload) {
		if (!virtqueue_has_free_buf(tx_vq)) {
			virtqueue_put_free_buf(tx_vq, pkt->hdr_buf_id);
			return -2;
		}
		pkt->payload_buf_id = virtqueue_get_free_buf_id(tx_vq);
		pkt->payload_buf = virtqueue_get_buf_by_id(tx_vq,
							   pkt->payload_buf_id);
		virtqueue_buffer_init(pkt->payload_buf, 0, 0);
		virtqueue_buffer_set_read_only(pkt->payload_buf);

		virtqueue_buffer_set_next(pkt->hdr_buf, pkt->payload_buf_id);
	} else {
		pkt->payload_buf = NULL;
	}

	return 0;
}

u32 vsock_dri_irq_id()
{
	assert(vsock_dev);
	return vsock_dev->irq_id;
}

u64 vsock_dri_cid(void)
{
	assert(vsock_dev);
	return vsock_dev->cid;
}

static void recycle_received_packet(struct vsock_pkt2 *pkt)
{
	struct virtqueue *rx_vq = &vsock_dev->vqueue.rx;
	assert(virtqueue_buffer_has_next(pkt->hdr_buf));
	virtqueue_put_avail_buf(rx_vq, pkt->hdr_buf_id);
	vsock_dri_notify(rx_vq);
}

static int process_incomming_connection_request(struct vsock_pkt2 *pkt)
{
	int err;
	struct vsock_socket *sock = get_socket_by_port(pkt->hdr.dst_port);

	if (sock == NULL) {
		vsd_warn("Got connection request on invalid port %u.\n",
			 pkt->hdr.dst_port);
		err = vsock_dri_reset_sender(pkt);
		assert(!err); // queueing limitation
		return -1;
	}
	if (sock->conn_status != CONN_STATUS_IN_OPEN) {
		vsd_warn("Got connection request for existing or outbound "
			 "connection.\n");
		err = vsock_dri_reset_sender(pkt);
		assert(!err); // queueing limitation
		return -2;
	}
	vsd_dbg("received connection request from cid=%llu\n",
		pkt->hdr.src_cid);

	sock->peer_cid = pkt->hdr.src_cid;
	sock->peer_port = pkt->hdr.src_port;
	sock->conn_status = CONN_STATUS_IN_CONNECTED;
	sock->fwd_cnt = 0;

	err = vsock_sock_send_ctrl_packet(sock, VIRTIO_VSOCK_OP_RESPONSE);
	assert(!err); // queueing limitation

	(void)err;
	return 0;
}

static int process_incomming_connection_response(struct vsock_pkt2 *pkt)
{
	int err;
	struct vsock_socket *sock = get_socket_by_port(pkt->hdr.dst_port);

	if (sock == NULL) {
		vsd_warn("Got connection response on invalid port %u.\n",
			 pkt->hdr.dst_port);
		err = vsock_dri_reset_sender(pkt);
		assert(!err); // queueing limitation
		return -1;
	}
	if (sock->conn_status != CONN_STATUS_OUT_REQUESTED) {
		vsd_warn("Got connection response for existing or inbound "
			 "connection.\n");
		err = vsock_dri_reset_sender(pkt);
		assert(!err); // queueing limitation
		return -2;
	}
	vsd_dbg("received connection response from cid=%llu\n",
		pkt->hdr.src_cid);

	sock->conn_status = CONN_STATUS_OUT_CONNECTED;
	sock->fwd_cnt = 0;

	(void)err;
	return 0;
}

static int process_incomming_connection_shutdown(struct vsock_pkt2 *pkt)
{
	int err;
	struct vsock_socket *sock = get_socket_by_port(pkt->hdr.dst_port);

	if (sock == NULL) {
		vsd_dbg("Got connection shutdown on invalid port %u.\n",
			pkt->hdr.dst_port);
		return 1;
	}
	if (sock->conn_status == CONN_STATUS_IN_CONNECTED) {
		sock->conn_status = CONN_STATUS_IN_OPEN;
	} else if (sock->conn_status == CONN_STATUS_OUT_CONNECTED) {
		sock->conn_status = CONN_STATUS_OUT_SHUTDOWN;
	} else {
		vsd_warn("Got connection shutdown for closed connection.\n");
		err = vsock_dri_reset_sender(pkt);
		assert(!err); // queueing limitation
		return -2;
	}
	vsd_dbg("received connection shutdown from cid=%llu\n",
		pkt->hdr.src_cid);

	err = vsock_sock_send_ctrl_packet(sock, VIRTIO_VSOCK_OP_SHUTDOWN);
	assert(!err); // queueing limitation
	err = vsock_sock_send_ctrl_packet(sock, VIRTIO_VSOCK_OP_RST);
	assert(!err); // queueing limitation

	(void)err;
	return 0;
}

static int process_incomming_connection_reset(struct vsock_pkt2 *pkt)
{
	struct vsock_socket *sock = get_socket_by_port(pkt->hdr.dst_port);

	if (sock == NULL) {
		vsd_dbg("Got connection reset on invalid port %u.\n",
			 pkt->hdr.dst_port);
		return 1;
	}
	if (sock->conn_status == CONN_STATUS_IN_CONNECTED) {
		sock->conn_status = CONN_STATUS_IN_OPEN;
	} else if (sock->conn_status == CONN_STATUS_OUT_CONNECTED
		   || sock->conn_status == CONN_STATUS_OUT_SHUTDOWN) {
		sock->conn_status = CONN_STATUS_OUT_DISCONNECTED;
	} else if (sock->conn_status == CONN_STATUS_OUT_REQUESTED) {
		sock->conn_status = CONN_STATUS_OUT_FAILED;
	} else {
		vsd_dbg("got connection reset for closed connection.\n");
		/* This is probably a reset after a successful shutdown. */
	}
	vsd_dbg("received connection reset from cid=%llu\n", pkt->hdr.src_cid);

	return 0;
}

/* executed in irq context */
void vsock_dri_irq_handler(u32 irqn)
{
	int err;
	struct virtqueue *rx_vq;
	struct virtqueue *tx_vq;
	struct virtq_desc *buf;
	struct virtq_used_elem *buf_hdr_elem;
	struct vsock_pkt2 *pkt;
	u16 buf_id, next_buf_id;
	u32 pkt_id;

	assert(vsock_dev);
	assert(irqn == vsock_dev->irq_id);

	rx_vq = &vsock_dev->vqueue.rx;
	tx_vq = &vsock_dev->vqueue.tx;

	while (virtqueue_used_has_buf(tx_vq)) {
		vsd_dbg("A tx buffer was returned\n");
		buf_hdr_elem = virtqueue_get_used_buf_elem(tx_vq);
		buf_id = (u16)buf_hdr_elem->id;

		pkt_id = vsock_dri_generate_packet_id(tx_vq, buf_id);
		if (vsock_dev->tx_handler) {
			vsock_dev->tx_handler(pkt_id,
					      vsock_dev->tx_handler_param);
		}

		buf = virtqueue_get_buf_by_id(tx_vq, buf_id);
		if (virtqueue_buffer_has_next(buf)) {
			next_buf_id = virtqueue_buffer_get_next_buf_id(buf);
			virtqueue_put_free_buf(tx_vq, next_buf_id);
		}
		virtqueue_put_free_buf(tx_vq, buf_id);
	}

	while (virtqueue_used_has_buf(rx_vq)) {
		vsd_dbg("An rx buffer was received\n");
		buf_hdr_elem = virtqueue_get_used_buf_elem(rx_vq);
		buf_id = (u16)buf_hdr_elem->id;

		pkt_id = vsock_dri_generate_packet_id(rx_vq, buf_id);
		pkt = vsock_dri_get_packet(pkt_id);

		/* fetch header */
		pkt->hdr_buf_id = (u16)buf_id;
		pkt->hdr_buf = virtqueue_get_buf_by_id(rx_vq, pkt->hdr_buf_id);
		assert(pkt->hdr_buf->len == sizeof(pkt->hdr));
		/* rx queue was prepared such that pkt.hdr = *hdr_buf.addr */
		assert(pkt->hdr.type == VIRTIO_VSOCK_TYPE_STREAM);
		assert(pkt->hdr.dst_cid == vsock_dev->cid);

		switch (pkt->hdr.op) {
			case VIRTIO_VSOCK_OP_REQUEST:
				err = process_incomming_connection_request(pkt);
				break;
			case VIRTIO_VSOCK_OP_RESPONSE:
				err = process_incomming_connection_response(
					      pkt);
				break;
			case VIRTIO_VSOCK_OP_RST:
				err = process_incomming_connection_reset(pkt);
				break;
			case VIRTIO_VSOCK_OP_SHUTDOWN:
				err = process_incomming_connection_shutdown(
					      pkt);
				break;
			case VIRTIO_VSOCK_OP_RW:
				err = 0;
				break;
			default:
				vsd_err("Received unsupported packet op %u\n",
					pkt->hdr.op);
				while(1);
		}
		if (err) {
			if (err < 0) {
				vsd_warn("ignoring buffer due to errors "
					 "(errno=%d)\n", err);
			}
			recycle_received_packet(pkt);
			continue;
		}

		/* fetch payload */
		if (pkt->hdr.op == VIRTIO_VSOCK_OP_RW && pkt->hdr.len != 0) {
			assert(virtqueue_buffer_has_next(pkt->hdr_buf));
			pkt->payload_buf_id = virtqueue_buffer_get_next_buf_id(
						      pkt->hdr_buf);
			pkt->payload_buf = virtqueue_get_buf_by_id(
						   rx_vq, pkt->payload_buf_id);
			assert(vsock_pkt_payload(pkt_id));
			/* we use the same assumption as Linux: data packets
			 * only consist of one header buffer and one payload
			 * buffer. */
			assert(!virtqueue_buffer_has_next(pkt->payload_buf));
		} else {
			pkt->payload_buf = NULL;
		}

//		printk("Header:\n"
//		       "\t- src_cid = %llu\n"
//		       "\t- dst_cid = %llu\n"
//		       "\t- src_port = %u\n"
//		       "\t- dst_port = %u\n"
//		       "\t- len = %u\n"
//		       "\t- type = %u\n"
//		       "\t- op = %u\n"
//		       "\t- flags = %u\n"
//		       "\t- buf_alloc = %u\n"
//		       "\t- fwd_cnt = %u\n", pkt->hdr.src_cid, pkt->hdr.dst_cid,
//		       pkt->hdr.src_port, pkt->hdr.dst_port, pkt->hdr.len,
//		       pkt->hdr.type, pkt->hdr.op, pkt->hdr.flags,
//		       pkt->hdr.buf_alloc, pkt->hdr.fwd_cnt);
//		printk("Payload size: %u\n", vsock_pkt_payload_size(pkt_id));

		struct vsock_socket *sock = get_socket_by_port(
					pkt->hdr.dst_port);
		if (sock == NULL) {
			if (pkt->hdr.op != VIRTIO_VSOCK_OP_RW) {
				/* ignoring ctrl packets for non existing
				 * sockets */
				continue;
			}
			vsd_warn("Got packet for invalid port %u.\n",
				 pkt->hdr.dst_port);
			err = vsock_dri_reset_sender(pkt);
			assert(!err); // queueing limitation
		} else if (pkt->hdr.op == VIRTIO_VSOCK_OP_RW
			   && sock->conn_status != CONN_STATUS_OUT_CONNECTED
			   && sock->conn_status != CONN_STATUS_IN_CONNECTED) {
			vsd_warn("Got data packet for not connected port %u.\n",
				 pkt->hdr.dst_port);
			err = vsock_dri_reset_sender(pkt);
			assert(!err); // queueing limitation
		} else {
			assert(sock->rx_handler);
			sock->fwd_cnt += vsock_pkt_payload_size(pkt_id);
			sock->rx_handler(pkt_id, sock->rx_handler_param);
		}
	}
}

void vsock_dri_register_on_send_completion(pkt_event_handler handler,
					      void *param)
{
	assert(vsock_dev);
	vsock_dev->tx_handler = handler;
	vsock_dev->tx_handler_param = param;
}

void vsock_pkt_free(u32 pkt_id)
{
	struct vsock_pkt2 *pkt = vsock_dri_get_packet(pkt_id);

	if (pkt_id & PKT_ID_BUF_RX) {
		vsd_dbg("Returning used packet 0x%x to RX queue\n", pkt_id);
		/* we don't care about security, so we don't zero the data */
		recycle_received_packet(pkt);
	} else if (pkt_id & PKT_ID_BUF_TX) {
		vsd_err("TX packets should be free'd by the tx_handler.\n");
	} else {
		vsd_err("Unimplemented: event queue in %s\n", __FUNCTION__);
	}
}

static int vsock_sock_send_ctrl_packet(struct vsock_socket *sock,
				       enum virtio_vsock_op op)
{
	return vsock_dri_send_ctrl_packet(sock->peer_cid, sock->peer_port,
					  sock->sock_port, op, sock->fwd_cnt);
}

static void vsock_dri_send_and_notify(struct vsock_pkt2 *pkt)
{
	struct virtqueue *tx_vq = &vsock_dev->vqueue.tx;

	virtqueue_put_avail_buf(tx_vq, pkt->hdr_buf_id);
	vsock_dri_notify(tx_vq);
}

static int vsock_dri_send_ctrl_packet(u64 dst_cid, u32 dst_port, u32 src_port,
				       enum virtio_vsock_op op, u32 fwd_cnt)
{
	int err;
	u32 pkt_h;
	struct vsock_pkt2 *pkt;

	err = prepare_packet_for_sending(&pkt_h, NO_PAYLOAD);
	if (err) {
		vsd_warn("No free tx buffer\n");
		return -1;
	}
	pkt = vsock_dri_get_packet(pkt_h);

	pkt->hdr.dst_cid = dst_cid;
	pkt->hdr.src_port = src_port;
	pkt->hdr.dst_port = dst_port;
	pkt->hdr.op = (u16)op;
	if (op == VIRTIO_VSOCK_OP_SHUTDOWN)
		pkt->hdr.flags = 0b11;
	pkt->hdr.fwd_cnt = fwd_cnt;

	vsd_dbg("Sending ctrl pkt (op=%u)\n", op);
	vsock_dri_send_and_notify(pkt);
	return 0;
}

static int vsock_dri_reset_sender(struct vsock_pkt2 *pkt)
{
	u32 fwd_cnt = 0;
	return vsock_dri_send_ctrl_packet(pkt->hdr.src_cid, pkt->hdr.src_port,
					  pkt->hdr.dst_port,
					  VIRTIO_VSOCK_OP_RST, fwd_cnt);
}

s64 vsock_dri_connection_listen(u32 port, pkt_event_handler rx_handler,
				void *rx_handler_param)
{
	int err;
	s64 fd;
	struct vsock_socket *sock;

	err = add_socket(&fd);

	if (err)
		return -1;

	vsd_dbg("listening on port %u\n", port);

	sock = get_socket_by_fd(fd);
	sock->rx_handler = rx_handler;
	sock->rx_handler_param = rx_handler_param;
	sock->peer_cid = 0;
	sock->peer_port = 0;
	sock->sock_port = port;
	sock->buf_alloc = BUFFER_SPACE_MGMT_BUF_ALLOC;
	sock->fwd_cnt = 0;
	sock->conn_status = CONN_STATUS_IN_OPEN;

	return fd;
}

s64 vsock_dri_connection_open(u64 dst_cid, u32 dst_port,
					 u32 src_port,
					 pkt_event_handler rx_handler,
					 void *rx_handler_param)
{
	int err;
	s64 fd;
	struct vsock_socket *sock;

	err = add_socket(&fd);
	if (err)
		return -1;

	vsd_dbg("setting up socket on port %u\n", src_port);

	sock = get_socket_by_fd(fd);
	sock->rx_handler = rx_handler;
	sock->rx_handler_param = rx_handler_param;
	sock->peer_cid = dst_cid;
	sock->peer_port = dst_port;
	sock->sock_port = src_port;
	sock->buf_alloc = BUFFER_SPACE_MGMT_BUF_ALLOC;
	sock->fwd_cnt = 0;
	sock->conn_status = CONN_STATUS_OUT_REQUESTED;

	err = vsock_sock_send_ctrl_packet(sock, VIRTIO_VSOCK_OP_REQUEST);
	assert(!err); // queueing limitation

	return fd;
}

int vsock_dri_connection_close(s64 fd)
{
	int err;
	struct vsock_socket *sock = get_socket_by_fd(fd);

	if (sock == NULL)
		return -1;

	switch(sock->conn_status) {
		case CONN_STATUS_IN_CONNECTED:
		case CONN_STATUS_OUT_CONNECTED:
			vsd_dbg("closing connection\n");
			err = vsock_sock_send_ctrl_packet(
				      sock, VIRTIO_VSOCK_OP_SHUTDOWN);
			assert(!err); // queueing limitation
			err = vsock_sock_send_ctrl_packet(sock,
							  VIRTIO_VSOCK_OP_RST);
			assert(!err); // queueing limitation
			break;
		default:
			vsd_dbg("closing already closed connection\n");
			break;
	}

	//TODO it's possible that some RX packets are still queued by the app we
	//     should try to recover them

	vsock_dev->sockets[fd] = NULL;

	(void)err;
	return 0;
}

bool vsock_sock_is_connected(s64 fd)
{
	struct vsock_socket *sock = get_socket_by_fd(fd);

	if (sock == NULL)
		return false;

	return sock->conn_status == CONN_STATUS_IN_CONNECTED
	       || sock->conn_status == CONN_STATUS_OUT_CONNECTED;
}

bool vsock_sock_connection_failed(s64 fd)
{
	struct vsock_socket *sock = get_socket_by_fd(fd);

	if (sock == NULL)
		return true;

	return sock->conn_status == CONN_STATUS_OUT_FAILED;
}

void *vsock_dri_get_rx_handler_param(s64 fd)
{
	struct vsock_socket *sock = get_socket_by_fd(fd);
	if (sock == NULL)
		return NULL;
	return sock->rx_handler_param;
}

int vsock_dri_send_data_packet(s64 fd, void *data, u32 data_size)
{
	int err;
	u32 pkt_id;
	struct vsock_pkt2 *pkt;
	struct vsock_socket *sock;

	sock = get_socket_by_fd(fd);

	if (sock == NULL) {
		vsd_err("Socket does not exist.\n");
		return -1;
	}
	if (sock->conn_status != CONN_STATUS_IN_CONNECTED
	    && sock->conn_status != CONN_STATUS_OUT_CONNECTED) {
		vsd_err("Socket is not connected.\n");
		return -2;
	}

	err = prepare_packet_for_sending(&pkt_id, HAS_PAYLOAD);
	if (err) {
		vsd_err("failed to prepare packet for sending (errno=%u)\n",
			err);
		return -1;
	}
	pkt = vsock_dri_get_packet(pkt_id);

	pkt->hdr.dst_cid = sock->peer_cid;
	pkt->hdr.src_port = sock->sock_port;
	pkt->hdr.dst_port = sock->peer_port;
	pkt->hdr.len = data_size;
	pkt->hdr.op = VIRTIO_VSOCK_OP_RW;
	pkt->hdr.fwd_cnt = sock->fwd_cnt;

	virtqueue_buffer_set_data(pkt->payload_buf, (u64)data, data_size);

	vsock_dri_send_and_notify(pkt);

	(void)err;
	return 0;
}

static int add_socket(s64 *sock)
{
	u32 i;
	for (i = 0; i < MAX_NUM_SOCKETS; ++i) {
		if (vsock_dev->sockets[i] == NULL)
			break;
	}
	if (i == MAX_NUM_SOCKETS)
		return -1;

	vsock_dev->sockets[i] = alloc(sizeof(*vsock_dev->sockets[i]),
				      sizeof(void*));
	*sock = i;
	return 0;
}

static struct vsock_socket *get_socket_by_fd(s64 fd)
{
	if(fd >= MAX_NUM_SOCKETS)
		return NULL;
	return vsock_dev->sockets[fd];
}

static struct vsock_socket *get_socket_by_port(u32 port)
{
	u32 i;
	for (i = 0; i < MAX_NUM_SOCKETS; ++i) {
		if (vsock_dev->sockets[i]->sock_port == port)
			return vsock_dev->sockets[i];
	}
	return NULL;
}

/* We are ignoring a lot of sanity checks here since we know the implementation
 * on the other side. */
int vsock_dri_connect_pci(void)
{
	int bdf;
	u8 cap_ptr, cap_type;
	u16 cmd, i;
	u32 tmp, bar0, bar0_size, cap_off;
	u32 *cid;
	u64 q_sz, desc_sz, used_sz, avail_sz;
	struct virtqueue *vq, *rx_vq;
	volatile struct virtio_pci_common_cfg *cmn_cfg;

	if (vsock_dev != NULL) {
		vsd_info("Vsock PCI device already connected.\n");
		return 0;
	}

	/* currently this seems to crash if the device ID is wrong and not return -1 */
	bdf = pci_find_device(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_ID_VSOCK,
			      0);
	if (bdf < 0) {
		vsd_info("No vsock PCI devices found.\n");
		return -1;
	}
	vsd_info("Found vsock PCI device at %02x:%02x.%x\n",
		 bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x7);

	vsock_dev = alloc(sizeof(*vsock_dev), sizeof(void*));
	memset(vsock_dev, 0, sizeof(*vsock_dev));
	vsock_dev->bdf = (u16)bdf;

	tmp = pci_read_config(vsock_dev->bdf, PCI_HEADER_TYPE, 2);
	assert(tmp == PCI_HEADER_TYPE_NORMAL);
	tmp = pci_read_config(vsock_dev->bdf, PCI_STATUS, 2);
	assert(tmp & PCI_STATUS_CAP_LIST);

	vsock_dev->irq_id = (u8)pci_read_config(vsock_dev->bdf,
						PCI_INTERRUPT_LINE, 1);
	vsd_dbg("irq id: %u\n", vsock_dev->irq_id);

	/* setup bar 0 */
	pci_write_config(vsock_dev->bdf, PCI_BASE_ADDRESS_0, 0xFFFFFFFF, 4);
	bar0 = pci_read_config(vsock_dev->bdf, PCI_BASE_ADDRESS_0, 4);
	vsd_dbg("bar0 read: 0x%08x\n", bar0);
	assert((bar0 & 0x7) == 0b000);
	bar0_size = ~(bar0 & 0xFFFFFFF0) + 1;
	assert(bar0_size == 0x1000);
	map_range((void*)BAR0_ADDR, bar0_size, MAP_UNCACHED);
	pci_write_config(vsock_dev->bdf, PCI_BASE_ADDRESS_0, BAR0_ADDR, 4);
	bar0 = pci_read_config(vsock_dev->bdf, PCI_BASE_ADDRESS_0, 4);
	vsd_dbg("bar0 read: 0x%08x\n", bar0);
	assert(bar0 == BAR0_ADDR);

	/* enable bar0 */
	cmd = (u16)pci_read_config(vsock_dev->bdf, PCI_COMMAND, 2);
	cmd |= PCI_COMMAND_MEMORY;
	pci_write_config(vsock_dev->bdf, PCI_COMMAND, cmd, 2);

	cap_ptr = (u8)pci_read_config(vsock_dev->bdf, PCI_CAPABILITY_LIST, 1);
	while (cap_ptr != 0) {
		cap_type = (u8)pci_read_config(vsock_dev->bdf, cap_ptr
					       + VIRTIO_PCI_CAP_CFG_TYPE, 1);
		cap_off = pci_read_config(vsock_dev->bdf, cap_ptr
					  + VIRTIO_PCI_CAP_OFFSET, 4);
		switch (cap_type) {
			case VIRTIO_PCI_CAP_COMMON_CFG:
				vsock_dev->cmn_cfg =
						(struct virtio_pci_common_cfg*)
						(BAR0_ADDR + cap_off);
				vsd_dbg("common cfg at 0x%08llx\n",
					(u64)vsock_dev->cmn_cfg);
				break;
			case VIRTIO_PCI_CAP_ISR_CFG:
				vsock_dev->isr = (u8*)(BAR0_ADDR + cap_off);
				vsd_dbg("isr status at 0x%08llx\n",
					(u64)vsock_dev->isr);
				break;
			case VIRTIO_PCI_CAP_DEVICE_CFG:
				cid = (u32*)(BAR0_ADDR + cap_off);
				vsock_dev->cid = mmio_read32(cid)
						 | (u64)mmio_read32(cid + 1)
						 << 32;
				vsd_dbg("cid is %llu\n", vsock_dev->cid);
				break;
			case VIRTIO_PCI_CAP_NOTIFY_CFG:
				vsock_dev->notify = (u16*)(BAR0_ADDR + cap_off);
				assert(pci_read_config(
					       vsock_dev->bdf, cap_ptr
					       + VIRTIO_PCI_NOTIFY_CAP_MULT, 4)
				       == sizeof(u16));
				vsd_dbg("notify region at 0x%08llx\n",
					(u64)vsock_dev->notify);
				break;
			default:
				vsd_err("Unknown capability type 0x%x!\n",
					cap_type);
		}
		cap_ptr = (u8)pci_read_config(vsock_dev->bdf, cap_ptr
					      + VIRTIO_PCI_CAP_NEXT, 1);
	}
	assert(vsock_dev->cmn_cfg);
	assert(vsock_dev->isr);
	assert(vsock_dev->notify);
	assert(vsock_dev->cid);
	cmn_cfg = vsock_dev->cmn_cfg;

	/* allow bus mastering (probably ignored, but just to be sure) */
	cmd = (u16)pci_read_config(vsock_dev->bdf, PCI_COMMAND, 2);
	cmd |= PCI_COMMAND_MASTER;
	pci_write_config(vsock_dev->bdf, PCI_COMMAND, cmd, 2);

	/* reset device */
	cmn_cfg->device_status = 0;
	assert(cmn_cfg->device_status == 0);
	cmn_cfg->device_status |= VIRTIO_CONFIG_S_ACKNOWLEDGE;
	assert(cmn_cfg->device_status & VIRTIO_CONFIG_S_ACKNOWLEDGE);
	cmn_cfg->device_status |= VIRTIO_CONFIG_S_DRIVER;
	cmn_cfg->guest_feature_select = 0;
	cmn_cfg->guest_feature = VIRTIO_SOCKET_FEATURE_BITS_LO;
	cmn_cfg->guest_feature_select = 1;
	cmn_cfg->guest_feature = VIRTIO_SOCKET_FEATURE_BITS_HI;
	cmn_cfg->device_status |= VIRTIO_CONFIG_S_FEATURES_OK;
	assert(!(cmn_cfg->device_status & 0xC0));

	u16 num_queues = cmn_cfg->num_queues;
	assert(num_queues == 3);
	(void)num_queues;

	/* setup virtqueues */
	for (i = 0; i < 3; ++i) {
		cmn_cfg->queue_select = i;
		vq = &vsock_dev->vqueues[i];

		q_sz = cmn_cfg->queue_size;
		vq->num = (u32)q_sz;
		assert(!cmn_cfg->queue_enable);
		assert(cmn_cfg->queue_notify_off == i);

		/* allocate locally */
		desc_sz = q_sz * sizeof(struct virtq_desc);
		used_sz = sizeof(struct virtq_used)
			  + q_sz * sizeof(struct virtq_used_elem);
		avail_sz = sizeof(struct virtq_avail) + q_sz * sizeof(u16);
		vq->desc = alloc(desc_sz, VIRTQ_DESC_ALIGN_SIZE);
		vq->used = alloc(used_sz, VIRTQ_USED_ALIGN_SIZE);
		vq->avail = alloc(avail_sz, VIRTQ_AVAIL_ALIGN_SIZE);

		/* setup virtqueue */
		memset((void*)vq->desc, 0, desc_sz);
		memset((void*)vq->used, 0, used_sz);
		memset((void*)vq->avail, 0, avail_sz);
		virtqueue_initialize_desc_tbl(vq);

		/* share with device */
		cmn_cfg->queue_desc_lo = (u32)(u64)vq->desc;
		cmn_cfg->queue_desc_hi = ((u64)vq->desc >> 32);
		cmn_cfg->queue_avail_lo = (u32)(u64)vq->avail;
		cmn_cfg->queue_avail_hi = ((u64)vq->avail >> 32);
		cmn_cfg->queue_used_lo = (u32)(u64)vq->used;
		cmn_cfg->queue_used_hi = ((u64)vq->used >> 32);
	}
	for (i = 0; i < 3; ++i) {
		cmn_cfg->queue_select = i;
		cmn_cfg->queue_enable = 1;
	}
	assert(vsock_dev->vqueue.rx.num == q_sz);
	assert(vsock_dev->vqueue.tx.num == q_sz);
	assert(vsock_dev->vqueue.event.num == q_sz);

	vsock_dev->rx_pkt_buffer = alloc(vsock_dev->vqueue.rx.num
					 * sizeof(*vsock_dev->rx_pkt_buffer),
					 sizeof(void*));
	vsock_dev->tx_pkt_buffer = alloc(vsock_dev->vqueue.tx.num
					 * sizeof(*vsock_dev->tx_pkt_buffer),
					 sizeof(void*));

	/* add buffers for RX queue */
	rx_vq = &vsock_dev->vqueue.rx;
	while(virtqueue_has_free_buf(rx_vq)) {
		add_empty_packet_to_virtqueue(rx_vq);
	}
	vsock_dri_notify(rx_vq);

	/* enable device */
	vsd_dbg("enabling device ...\n");
	cmn_cfg->device_status |= VIRTIO_CONFIG_S_DRIVER_OK;
	assert(!(cmn_cfg->device_status & 0xC0));
	vsd_dbg("device enabled\n");

	(void)tmp;
	return 0;
}

u32 vsock_dri_queue_size(void)
{
	assert(vsock_dev);
	return vsock_dev->vqueue.rx.num;
}

static inline void vsock_dri_notify(struct virtqueue *vq)
{
	if (vq == &vsock_dev->vqueue.rx)
		vsock_dev->notify[0] = 1;
	else if (vq == &vsock_dev->vqueue.tx)
		vsock_dev->notify[1] = 1;
	else
		vsock_dev->notify[2] = 1;
}

#define HEADER_ALIGNMENT	8
#define PAYLOAD_ALIGNMENT	8
/* does not notify */
void add_empty_packet_to_virtqueue(struct virtqueue *vq)
{
	u16 buf_id;
	u32 pkt_id;
	struct vsock_pkt2 *pkt;
	u32 payload_size = RX_PACKET_SIZE;
	void *payload;

	vsd_dbg("Preparing rx packet\n");

	assert(virtqueue_has_free_buf(vq));
	buf_id = virtqueue_get_free_buf_id(vq);
	pkt_id = vsock_dri_generate_packet_id(vq, buf_id);
	pkt = vsock_dri_get_packet(pkt_id);

	pkt->hdr_buf_id = buf_id;
	pkt->hdr_buf = virtqueue_get_buf_by_id(vq, pkt->hdr_buf_id);
	virtqueue_buffer_init(pkt->hdr_buf, (u64)&pkt->hdr, sizeof(pkt->hdr));
	virtqueue_buffer_set_read_write(pkt->hdr_buf);
	memset(&pkt->hdr, 0, sizeof(pkt->hdr));

	assert(virtqueue_has_free_buf(vq));
	pkt->payload_buf_id = virtqueue_get_free_buf_id(vq);
	pkt->payload_buf = virtqueue_get_buf_by_id(vq, pkt->payload_buf_id);

	payload = alloc(payload_size, PAYLOAD_ALIGNMENT);
	virtqueue_buffer_init(pkt->payload_buf, (u64)payload, payload_size);
	virtqueue_buffer_set_read_write(pkt->payload_buf);

	virtqueue_buffer_set_next(pkt->hdr_buf, pkt->payload_buf_id);

	virtqueue_put_avail_buf(vq, pkt->hdr_buf_id);
}
