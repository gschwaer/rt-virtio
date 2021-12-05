/** 
 * Bao, a Lightweight Static Partitioning Hypervisor 
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *      Sandro Pinto <sandro.pinto@bao-project.org>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details. 
 *
 */

#define ENTRY_SIZE   (0x80)

.macro SAVE_REGS

    sub sp, sp, #(22 * 8)

    stp x0, x1,   [sp, #(8*0)]
    stp x2, x3,   [sp, #(8*2)]
    stp x4, x5,   [sp, #(8*4)]
    stp x6, x7,   [sp, #(8*6)]
    stp x8, x9,   [sp, #(8*8)]
    stp x10, x11, [sp, #(8*10)]
    stp x12, x13, [sp, #(8*12)]
    stp x14, x15, [sp, #(8*14)]
    stp x16, x17, [sp, #(8*16)]
    stp x18, x19, [sp, #(8*18)]
    stp x29, x30, [sp, #(8*28)]
.endm

.macro RESTORE_REGS
    ldp x0, x1,   [sp, #(8*0)]
    ldp x2, x3,   [sp, #(8*2)]
    ldp x4, x5,   [sp, #(8*4)]
    ldp x6, x7,   [sp, #(8*6)]
    ldp x8, x9,   [sp, #(8*8)]
    ldp x10, x11, [sp, #(8*10)]
    ldp x12, x13, [sp, #(8*12)]
    ldp x14, x15, [sp, #(8*14)]
    ldp x16, x17, [sp, #(8*16)]
    ldp x18, x19, [sp, #(8*18)]
    ldp x29, x30, [sp, #(8*28)]

    add sp, sp, #(22 * 8)
.endm

/* From jailhouse/inmates/lib/arm64/header.S
 *
 * Jailhouse AArch64 support
 *
 * Copyright (C) 2015 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 *  Antonios Motakis <antonios.motakis@huawei.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2. */
.macro	SAVE_ALL_REGS
	stp x0, x1, [sp, #(0 * 16)]
	stp x2, x3, [sp, #(1 * 16)]
	stp x4, x5, [sp, #(2 * 16)]
	stp x6, x7, [sp, #(3 * 16)]
	stp x8, x9, [sp, #(4 * 16)]
	stp x10, x11, [sp, #(5 * 16)]
	stp x12, x13, [sp, #(6 * 16)]
	stp x14, x15, [sp, #(7 * 16)]
	stp x16, x17, [sp, #(8 * 16)]
	stp x18, x19, [sp, #(9 * 16)]
	stp x20, x21, [sp, #(10 * 16)]
	stp x22, x23, [sp, #(11 * 16)]
	stp x24, x25, [sp, #(12 * 16)]
	stp x26, x27, [sp, #(13 * 16)]
	stp x28, x29, [sp, #(14 * 16)]
.endm

.macro	RESTORE_ALL_REGS
	ldp x0, x1, [sp, #(0 * 16)]
	ldp x2, x3, [sp, #(1 * 16)]
	ldp x4, x5, [sp, #(2 * 16)]
	ldp x6, x7, [sp, #(3 * 16)]
	ldp x8, x9, [sp, #(4 * 16)]
	ldp x10, x11, [sp, #(5 * 16)]
	ldp x12, x13, [sp, #(6 * 16)]
	ldp x14, x15, [sp, #(7 * 16)]
	ldp x16, x17, [sp, #(8 * 16)]
	ldp x18, x19, [sp, #(9 * 16)]
	ldp x20, x21, [sp, #(10 * 16)]
	ldp x22, x23, [sp, #(11 * 16)]
	ldp x24, x25, [sp, #(12 * 16)]
	ldp x26, x27, [sp, #(13 * 16)]
	ldp x28, x29, [sp, #(14 * 16)]
.endm

.macro	JUMP_VECTOR_SYNC
    sub 	sp, sp, #(17 * 16)
    SAVE_ALL_REGS

    /* ABI: misuse x18 */
    mrs	x16, ELR_EL1
    mrs	x17, ESR_EL1
    mrs	x18, FAR_EL1
    stp	x30, x18, [sp, #(15 * 16)]
    stp	x16, x17, [sp, #(16 * 16)]

    mov x0, sp
    b	vector_sync
.endm
/* End of code from jailhouse/inmates/lib/arm64/header.S */

.balign 0x800
.global _exception_vector
_exception_vector:
/* 
 * EL1 with SP0
 */  
.balign ENTRY_SIZE
curr_el_sp0_sync:        
    b	.
.balign ENTRY_SIZE
curr_el_sp0_irq:  
    b   .
.balign ENTRY_SIZE
curr_el_sp0_fiq:         
    b	.
.balign ENTRY_SIZE
curr_el_sp0_serror:      
    b	.
          

/* 
 * EL1 with SPx
 */  
.balign ENTRY_SIZE  
curr_el_spx_sync:        
    JUMP_VECTOR_SYNC
    b	.
.balign ENTRY_SIZE
curr_el_spx_irq:       
    SAVE_REGS
    bl	gic_handle
    RESTORE_REGS
    eret
.balign ENTRY_SIZE
curr_el_spx_fiq:         
    SAVE_REGS
    bl	gic_handle
    RESTORE_REGS
    eret
.balign ENTRY_SIZE
curr_el_spx_serror:      
    b	.         

/* 
 * Lower EL using AArch64
 */  

.balign ENTRY_SIZE
lower_el_aarch64_sync:
    b .
.balign ENTRY_SIZE
lower_el_aarch64_irq:    
    b .
.balign ENTRY_SIZE
lower_el_aarch64_fiq:    
    b	.
.balign ENTRY_SIZE
lower_el_aarch64_serror: 
    b	.          

/* 
 * Lower EL using AArch32
 */  
.balign ENTRY_SIZE   
lower_el_aarch32_sync:   
    b	.
.balign ENTRY_SIZE
lower_el_aarch32_irq:    
    b	.
.balign ENTRY_SIZE
lower_el_aarch32_fiq:    
    b	.
.balign ENTRY_SIZE
lower_el_aarch32_serror: 
    b	.

.balign ENTRY_SIZE      