#ifndef VIRTIO_SOCKET_DRIVER_H
#define VIRTIO_SOCKET_DRIVER_H

#include <inmate.h>

/* connect to pci device */
int vsock_dri_connect_pci(void);
/* get queue size */
u32 vsock_dri_queue_size(void);
/* irq id used by the vsock driver */
u32 vsock_dri_irq_id(void);
/* cid assigned by the hypervisor */
u64 vsock_dri_cid(void);
/* handler to be called on the above irq */
void vsock_dri_irq_handler(u32 irqn);

//TODO doc
typedef void (*pkt_event_handler)(u32 pkt_id, void *param);
void vsock_dri_register_on_send_completion(pkt_event_handler handler,
					   void *param);
s64 vsock_dri_connection_listen(u32 port, pkt_event_handler rx_handler,
				void *rx_handler_param);
s64 vsock_dri_connection_open(u64 dst_cid, u32 dst_port, u32 src_port,
			      pkt_event_handler rx_handler,
			      void *rx_handler_param);
int vsock_dri_connection_close(s64 fd);
bool vsock_sock_is_connected(s64 fd);
bool vsock_sock_connection_failed(s64 fd);
void *vsock_dri_get_rx_handler_param(s64 fd);

/* returns
 * 0 on success
 * -1 on peer not connected
 * -2 on .. */
int vsock_dri_send_data_packet(s64 fd, void *data, u32 data_size);

bool vsock_pkt_is_data_pkt(u32 pkt);
u32 vsock_pkt_payload_size(u32 pkt);
void *vsock_pkt_payload(u32 pkt);
/* must be called for each received packet! */
void vsock_pkt_free(u32 pkt);

#endif /* VIRTIO_SOCKET_DRIVER_H */
