/*
 * FreeRTOS Kernel V10.2.1
 * Copyright (C) 2019 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 *
 * 1 tab == 4 spaces!
 */

/* FreeRTOS kernel includes. */
#include <FreeRTOS.h>
#include <task.h>
#include <queue.h>

#include <stdio.h>

#include <uart.h>
#include <irq.h>
#include <plat.h>


#include "vsock.h"

#define DEBUG 1

#define PRINT_PREFIX "FreeRTOS-app"
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

/*
 * Prototypes for the standard FreeRTOS callback/hook functions implemented
 * within this file.  See https://www.freertos.org/a00016.html
 */
void vApplicationMallocFailedHook(void);
void vApplicationIdleHook(void);
void vApplicationStackOverflowHook(TaskHandle_t pxTask, char *pcTaskName);
void vApplicationTickHook(void);

#define TASK_PRIO_SEND_TASK	(tskIDLE_PRIORITY + 1)		// 1
#define TASK_PRIO_RECV_TASK	(tskIDLE_PRIORITY + 1)		// 1

#define TASK_STK_SZ_SEND_TASK	4096
#define TASK_STK_SZ_RECV_TASK	4096

/*-----------------------------------------------------------*/

__attribute__((noreturn))
void recvTask(void *pvParam)
{
	(void)pvParam;
	PacketHandle_t xPacketHandle;
	SocketHandle_t xSocketHandle;
	UBaseType_t uxPayloadSize;
	void *pvPayload;
	const char pcResp[] = " to you too!";
	UBaseType_t uxDataSize;
	void *pvData;

	xSocketHandle = xVsockListenOn(1234);
	assert(xSocketHandle >= 0);

	while (1) {
		xPacketHandle = xVsockWaitForDataPacket(xSocketHandle);
		uxPayloadSize = uxVsockPacketPayload(xPacketHandle, &pvPayload);

		info_print("Got a message, %lu chars: \"%.*s\"\n",
			   uxPayloadSize, (int)uxPayloadSize, (char*)pvPayload);

		/* add response string to payload */
		uxDataSize = uxPayloadSize-1 + sizeof(pcResp);
		pvData = pvPortMalloc(uxDataSize);
		memcpy(pvData, pvPayload, uxPayloadSize-1);
		vVsockFreeReceivedPacket(xPacketHandle);
		memcpy(pvData + (uxPayloadSize-1), pcResp, sizeof(pcResp));

		info_print("Sending response: \"%s\"\n", pvData);
		vVsockSendData(xSocketHandle, pvData, uxDataSize);
	}
}

static bool try_send = false;

__attribute__((noreturn))
void sendTask(void *pvParam)
{
	(void)pvParam;
	PacketHandle_t xPacketHandle;
	SocketHandle_t xSocketHandle;
	UBaseType_t uxPayloadSize;
	void *pvPayload;
	const char pcMsg[] = "Hello there, you can call me FreeRTOS!";
	char *pcData;

	UBaseType_t uxCid = (uxVsockGetOwnCID() == 3 ? 4 : 3);
	UBaseType_t uxPort = 1234;

	while (1) {
		dbg_print("Sender Task: waiting for UART input ..\n");
		vTaskDelay(pdMS_TO_TICKS(200));

		if (uxVsockGetOwnCID() == 3)
			try_send = true;

		if (!try_send)
			continue;

		dbg_print("Connecting to %lu:%lu\n", uxCid, uxPort);
		xSocketHandle = xVsockConnectTo(uxCid, uxPort);
		assert(xSocketHandle >= 0);

		info_print("Sending message: \"%s\"\n", pcMsg);
		pcData = pvPortMalloc(sizeof(pcMsg));
		memcpy(pcData, pcMsg, sizeof(pcMsg));
		vVsockSendData(xSocketHandle, pcData, sizeof(pcMsg));

		xPacketHandle = xVsockWaitForDataPacket(xSocketHandle);
		uxPayloadSize = uxVsockPacketPayload(xPacketHandle, &pvPayload);

		info_print("Got a response, %lu chars: \"%.*s\"\n",
			   uxPayloadSize, (int)uxPayloadSize, (char*)pvPayload);
		vVsockFreeReceivedPacket(xPacketHandle);

		vVsockClose(xSocketHandle);
		try_send = false;
		dbg_print("End of transfer.\n");
	}
}

/* executed in irq context */
void uart_rx_handler(){
	dbg_print("%s\n", __func__);
	uart_clear_rxirq();
	try_send = true;
}

#define TOTAL_CELL_MEM_SIZE		0x10000000
/* Used by retarget.c for setup of mapping before any other initialization is
 * done. Accesses in the initialization would result in exceptions otherwise. */
void inmate_init(void);
void inmate_init(void)
{
	/* Only use printk here since the uart for printf is not initialized yet
	 * and cannot be initialized before the mapping was done. */

	/* standard arm64 inmate init */
	arch_mmu_enable();
	if (comm_region->revision != COMM_REGION_ABI_REVISION ||
	    memcmp(comm_region->signature, COMM_REGION_MAGIC,
		   sizeof(comm_region->signature))) {
		comm_region->cell_state = JAILHOUSE_CELL_FAILED_COMM_REV;
		stop();
	}
	/* Map rest of the inmate's memory */
	map_range((void*)CONFIG_INMATE_BASE + 0x10000,
		  TOTAL_CELL_MEM_SIZE - 0x10000, MAP_CACHED);
	/* Map uart */
	map_range((void*)UART_ADDRESS, 0x1000, MAP_UNCACHED);
	/* Map GICD & GICC */
	map_range((void*)0xF9010000, 0x1000, MAP_UNCACHED);
#ifndef VIRTUALIZED_GICC
	map_range((void*)0xF9020000, 0x1000, MAP_UNCACHED);
#else
	map_range((void*)0xF902F000, 0x1000, MAP_UNCACHED);
#endif
//	extern char _heap_base;
//	printk("inmate heap top 0x%06lx freertos heap base 0x%06llx", heap_pos,
//	       (u64)&_heap_base);
}

int main(void)
{
	info_print("Jailhouse FreeRTOS guest\n");

	vVsockInit();

	extern char _heap_base[];
	printk("jh heap used: %lu bytes\n", heap_pos - (unsigned long)stack_top);
	printk("max: %lu bytes\n", (unsigned long)_heap_base - (unsigned long)stack_top);

	uart_enable_rxirq();
	irq_set_handler(UART_IRQ_ID, uart_rx_handler);
	irq_enable(UART_IRQ_ID);
	irq_set_prio(UART_IRQ_ID, 1 << portPRIORITY_SHIFT);

	xTaskCreate(sendTask, "sendT", 2*TASK_STK_SZ_SEND_TASK, NULL,
		    TASK_PRIO_SEND_TASK, NULL);
	xTaskCreate(recvTask, "recvT", 2*TASK_STK_SZ_RECV_TASK, NULL,
		    TASK_PRIO_RECV_TASK, NULL);

	vTaskStartScheduler();
}
/*-----------------------------------------------------------*/

__attribute__((noreturn))
void vApplicationMallocFailedHook(void)
{
	/* vApplicationMallocFailedHook() will only be called if
	configUSE_MALLOC_FAILED_HOOK is set to 1 in FreeRTOSConfig.h.  It is a hook
	function that will get called if a call to pvPortMalloc() fails.
	pvPortMalloc() is called internally by the kernel whenever a task, queue,
	timer or semaphore is created.  It is also called by various parts of the
	demo application.  If heap_1.c or heap_2.c are used, then the size of the
	heap available to pvPortMalloc() is defined by configTOTAL_HEAP_SIZE in
	FreeRTOSConfig.h, and the xPortGetFreeHeapSize() API function can be used
	to query the size of free heap space that remains (although it does not
	provide information on how the remaining heap might be fragmented). */
	taskDISABLE_INTERRUPTS();
	err_print("malloc failed!\n");
	for (;;)
		;
}
/*-----------------------------------------------------------*/

void vApplicationIdleHook(void)
{
	/* vApplicationIdleHook() will only be called if configUSE_IDLE_HOOK is set
	to 1 in FreeRTOSConfig.h.  It will be called on each iteration of the idle
	task.  It is essential that code added to this hook function never attempts
	to block in any way (for example, call xQueueReceive() with a block time
	specified, or call vTaskDelay()).  If the application makes use of the
	vTaskDelete() API function (as this demo application does) then it is also
	important that vApplicationIdleHook() is permitted to return to its calling
	function, because it is the responsibility of the idle task to clean up
	memory allocated by the kernel to any task that has since been deleted. */
}
/*-----------------------------------------------------------*/

__attribute__((noreturn))
void vApplicationStackOverflowHook(TaskHandle_t pxTask, char *pcTaskName)
{
	(void)pcTaskName;
	(void)pxTask;

	/* Run time stack overflow checking is performed if
	configCHECK_FOR_STACK_OVERFLOW is defined to 1 or 2.  This hook
	function is called if a stack overflow is detected. */
	taskDISABLE_INTERRUPTS();
	err_print("stack overflow!\n");
	for (;;)
		;
}
/*-----------------------------------------------------------*/

void vApplicationTickHook(void)
{
}
/*-----------------------------------------------------------*/

/* This version of vApplicationAssert() is declared as a weak symbol to allow it
to be overridden by a version implemented within the application that is using
this BSP. */
void vApplicationAssert( const char *pcFileName, uint32_t ulLine )
{
	volatile uint32_t ul = 0;
	volatile const char *pcLocalFileName = pcFileName; /* To prevent pcFileName being optimized away. */
	volatile uint32_t ulLocalLine = ulLine; /* To prevent ulLine being optimized away. */

	/* Prevent compile warnings about the following two variables being set but
	not referenced.  They are intended for viewing in the debugger. */
	( void ) pcLocalFileName;
	( void ) ulLocalLine;

	/* If this function is entered then a call to configASSERT() failed in the
	FreeRTOS code because of a fatal error.  The pcFileName and ulLine
	parameters hold the file name and line number in that file of the assert
	that failed.  Additionally, if using the debugger, the function call stack
	can be viewed to find which line failed its configASSERT() test.  Finally,
	the debugger can be used to set ul to a non-zero value, then step out of
	this function to find where the assert function was entered. */
	taskENTER_CRITICAL();
	err_print( "Assert failed in %s:%u\n", pcLocalFileName, ulLocalLine );
	{
		while( ul == 0 )
		{
			__asm volatile( "NOP" );
		}
	}
	taskEXIT_CRITICAL();
}
