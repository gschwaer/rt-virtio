#include "vsock.h"

/* FreeRTOS */
#include <queue.h>

/* Arm Baremetal Runtime */
#include <irq.h>

/* Jailhouse */
#include <inmate.h>
#include <virtio-socket-driver.h>

#include <stdio.h>


#define MAX_NUM_SOCKETS		10

#define DEBUG 0

#define PRINT_PREFIX "FreeRTOS-vsock"
#define err_print(...) printf(PRINT_PREFIX " (error): " __VA_ARGS__)
#if DEBUG == 2
#define dbg_print(...) printf(PRINT_PREFIX " (debug): " __VA_ARGS__)
#else
#define dbg_print(...)
#endif
#if DEBUG >= 1
#define info_print(...) printf(PRINT_PREFIX " (info): " __VA_ARGS__)
#else
#define info_print(...)
#endif


/* Limited to 16383 opening of an outbound socket. */
#define FIRST_DYN_PORT		49152
#define LAST_DYN_PORT		65535
static u16 usDynPort = FIRST_DYN_PORT;


/* executed in irq context */
void vVsockEnqueueOnReceive(PacketHandle_t xPacket, void *pvParam)
{
	BaseType_t xErr;
	BaseType_t xHigherPriorityTaskWoken;
	QueueHandle_t xRXQueue = pvParam;

	xErr = xQueueSendFromISR(xRXQueue, &xPacket, &xHigherPriorityTaskWoken);
	configASSERT(xErr != pdFALSE);

	portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
}

/* executed in irq context */
void vEnqueueOnSendCompletion(PacketHandle_t xPacket, void *pvParam)
{
	BaseType_t xErr;
	BaseType_t xHigherPriorityTaskWoken = pdFALSE;
	QueueHandle_t xFreeQueue = pvParam;
	void *pvPayload;

	pvPayload = vsock_pkt_payload(xPacket);
	if (pvPayload != NULL) {
		xErr = xQueueSendFromISR(xFreeQueue, &pvPayload,
					 &xHigherPriorityTaskWoken);
		/* This could theoretically fail if freeTask is not executed
		 * fast enough between data sending, so we should give the
		 * freeTask a high priority. */
		configASSERT(xErr != pdFALSE);
	}

	portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
}

enum PacketType_e {
	PACKET_TYPE_ANY,
	PACKET_TYPE_CONTROL,
	PACKET_TYPE_DATA
};
static PacketHandle_t xVsockWaitForPacket(SocketHandle_t xSocketHandle,
					  enum PacketType_e xType)
{
	void *pvRXHandlerParam;
	BaseType_t xErr;
	QueueHandle_t xMsgQueue;
	PacketHandle_t xPacketHandle;

	pvRXHandlerParam = vsock_dri_get_rx_handler_param(xSocketHandle);
	configASSERT(pvRXHandlerParam != NULL);
	xMsgQueue = (QueueHandle_t)pvRXHandlerParam;

	while (1) {
		xErr = xQueueReceive(xMsgQueue, &xPacketHandle, portMAX_DELAY);
		configASSERT(xErr != pdFALSE);

		if (xType == PACKET_TYPE_ANY)
			break;
		if (xType == PACKET_TYPE_DATA
		    && vsock_pkt_is_data_pkt(xPacketHandle))
			break;
		if (xType == PACKET_TYPE_CONTROL
		    && !vsock_pkt_is_data_pkt(xPacketHandle))
			break;

		dbg_print("Skipping packet\n");
		vVsockFreeReceivedPacket(xPacketHandle);
	}

	return xPacketHandle;
}

PacketHandle_t xVsockWaitForControlPacket(SocketHandle_t xSocketHandle)
{
	return xVsockWaitForPacket(xSocketHandle, PACKET_TYPE_CONTROL);
}

PacketHandle_t xVsockWaitForAnyPacket(SocketHandle_t xSocketHandle)
{
	return xVsockWaitForPacket(xSocketHandle, PACKET_TYPE_ANY);
}

PacketHandle_t xVsockWaitForDataPacket(SocketHandle_t xSocketHandle)
{
	return xVsockWaitForPacket(xSocketHandle, PACKET_TYPE_DATA);
}

void vVsockFreeReceivedPacket(PacketHandle_t xPacketHandle)
{
	vsock_pkt_free(xPacketHandle);
}

void vVsockSendData(SocketHandle_t xSocketHandle, void *pvData,
		    UBaseType_t uxSize)
{
	int err;

	configASSERT(uxSize <= UINT32_MAX);
	err = vsock_dri_send_data_packet(xSocketHandle, pvData, (u32)uxSize);
	configASSERT(!err);
}

BaseType_t xVsockConnectionEstablished(SocketHandle_t xSocketHandle)
{
	return (vsock_sock_is_connected(xSocketHandle) ? pdTRUE : pdFALSE);
}

BaseType_t xVsockConnectionTerminated(SocketHandle_t xSocketHandle)
{
	return (vsock_sock_connection_failed(xSocketHandle) ? pdTRUE : pdFALSE);
}

SocketHandle_t xVsockConnectTo(UBaseType_t uxCID, UBaseType_t uxPortID)
{
	QueueHandle_t xMsgQueue;
	SocketHandle_t xSocketHandle;
	PacketHandle_t xPacketHandle;

	xMsgQueue = xQueueCreate(vsock_dri_queue_size(),
				 sizeof(PacketHandle_t));
	configASSERT(xMsgQueue != 0);

	assert(uxPortID <= UINT32_MAX);
	xSocketHandle = vsock_dri_connection_open(uxCID, (u32)uxPortID,
						  usDynPort++,
						  vVsockEnqueueOnReceive,
						  xMsgQueue);

	while (1) {
		xPacketHandle = xVsockWaitForAnyPacket(xSocketHandle);
		configASSERT(!vsock_pkt_is_data_pkt(xPacketHandle));
		vVsockFreeReceivedPacket(xPacketHandle);

		if (xVsockConnectionEstablished(xSocketHandle) != pdFALSE) {
			break;
		}
		if (xVsockConnectionTerminated(xSocketHandle)) {
			err_print("Failed to connect!\n");
			return -1;
		}
	}

	return xSocketHandle;
}

SocketHandle_t xVsockListenOn(UBaseType_t uxPortID)
{
	QueueHandle_t xMsgQueue;

	xMsgQueue = xQueueCreate(vsock_dri_queue_size(),
				 sizeof(PacketHandle_t));
	configASSERT(xMsgQueue != 0);

	assert(uxPortID <= UINT32_MAX);
	return vsock_dri_connection_listen((u32)uxPortID,
					   vVsockEnqueueOnReceive, xMsgQueue);
}

void vVsockClose(SocketHandle_t xSocketHandle)
{
	void *pvRXHandlerParam;
	BaseType_t xErr;
	QueueHandle_t xMsgQueue;
	PacketHandle_t xPacketHandle;

	pvRXHandlerParam = vsock_dri_get_rx_handler_param(xSocketHandle);
	configASSERT(pvRXHandlerParam != NULL);
	xMsgQueue = (QueueHandle_t)pvRXHandlerParam;

	/* drain the packet queue */
	while (1) {
		xErr = xQueueReceive(xMsgQueue, &xPacketHandle, 0);
		if (xErr == pdFALSE)
			break;
		vVsockFreeReceivedPacket(xPacketHandle);
	}
	vsock_dri_connection_close(xSocketHandle);

	vQueueDelete(xMsgQueue);
}

#define TASK_PRIO_FREE_TASK	(configMAX_PRIORITIES - 1)	// 7
#define TASK_STK_SZ_FREE_TASK	256
__attribute__((noreturn))
void vFreeTask(void *pvParam)
{
	QueueHandle_t xFreeQueue = pvParam;
	BaseType_t xErr;
	void *pvPayload;

	while (1) {
		xErr = xQueueReceive(xFreeQueue, &pvPayload, portMAX_DELAY);
		configASSERT(xErr != pdFALSE);

		vPortFree(pvPayload);
		dbg_print("Free'd packet payload at 0x%llx\n", (u64)pvPayload);
	}
}

void vVsockInit()
{
	QueueHandle_t xFreeQueue;

	pci_init();
	vsock_dri_connect_pci();

	xFreeQueue = xQueueCreate(vsock_dri_queue_size(), sizeof(void*));
	configASSERT(xFreeQueue != 0);

	vsock_dri_register_on_send_completion(vEnqueueOnSendCompletion,
					      xFreeQueue);
	irq_set_handler(vsock_dri_irq_id(), vsock_dri_irq_handler);
	irq_enable(vsock_dri_irq_id());
	irq_set_prio(vsock_dri_irq_id(), configMAX_API_CALL_INTERRUPT_PRIORITY
					 << portPRIORITY_SHIFT);

	xTaskCreate(vFreeTask, "VsockFree", TASK_STK_SZ_FREE_TASK,
		    (void *)xFreeQueue, TASK_PRIO_FREE_TASK, NULL);
}

UBaseType_t uxVsockGetOwnCID(void)
{
	return vsock_dri_cid();
}


UBaseType_t uxVsockPacketPayload(PacketHandle_t xPacketHandle, void **ppvPayload)
{
	*ppvPayload = vsock_pkt_payload(xPacketHandle);
	return vsock_pkt_payload_size(xPacketHandle);
}
