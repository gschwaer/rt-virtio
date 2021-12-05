#ifndef VSOCK_H
#define VSOCK_H

#include <FreeRTOS.h>

#include <inmate.h>

typedef u32 PacketHandle_t;
typedef s64 SocketHandle_t;

void
vVsockInit(void);

UBaseType_t
uxVsockGetOwnCID(void);

SocketHandle_t
xVsockConnectTo(UBaseType_t uxCID, UBaseType_t uxPortID);

/* returns pdTRUE or pdFALSE */
BaseType_t
xVsockConnectionEstablished(SocketHandle_t xSocketHandle);

/* returns pdTRUE or pdFALSE */
BaseType_t
xVsockConnectionTerminated(SocketHandle_t xSocketHandle);

void
vVsockSendData(SocketHandle_t xSocketHandle, void *pvData, UBaseType_t uxSize);

PacketHandle_t
xVsockWaitForAnyPacket(SocketHandle_t xSocketHandle);

PacketHandle_t
xVsockWaitForControlPacket(SocketHandle_t xSocketHandle);

PacketHandle_t
xVsockWaitForDataPacket(SocketHandle_t xSocketHandle);

void
vVsockFreeReceivedPacket(PacketHandle_t xPacketHandle);

/* Create passive socket */
SocketHandle_t
xVsockListenOn(UBaseType_t uxPortID);

void
vVsockClose(SocketHandle_t xSocketHandle);


/* returns payload size and puts pointer to payload in ppvPayload */
UBaseType_t
uxVsockPacketPayload(PacketHandle_t xPacketHandle, void **ppvPayload);

#endif /* VSOCK_H */
