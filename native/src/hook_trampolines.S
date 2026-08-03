.text
.p2align 2

.globl _WechatBridgeReq2BufEnterHook
_WechatBridgeReq2BufEnterHook:
    sub sp, sp, #0x120
    stp x0, x1, [sp, #0x00]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    stp x8, x9, [sp, #0x40]
    stp x10, x11, [sp, #0x50]
    stp x12, x13, [sp, #0x60]
    stp x14, x15, [sp, #0x70]
    stp x16, x17, [sp, #0x80]
    str x30, [sp, #0x90]
    stp q0, q1, [sp, #0xa0]
    stp q2, q3, [sp, #0xc0]
    stp q4, q5, [sp, #0xe0]
    stp q6, q7, [sp, #0x100]
    mov x0, x1
    mov x1, x24
    bl _WechatBridgeHandleReq2BufEnter
    ldp q6, q7, [sp, #0x100]
    ldp q4, q5, [sp, #0xe0]
    ldp q2, q3, [sp, #0xc0]
    ldp q0, q1, [sp, #0xa0]
    ldr x30, [sp, #0x90]
    ldp x16, x17, [sp, #0x80]
    ldp x14, x15, [sp, #0x70]
    ldp x12, x13, [sp, #0x60]
    ldp x10, x11, [sp, #0x50]
    ldp x8, x9, [sp, #0x40]
    ldp x6, x7, [sp, #0x30]
    ldp x4, x5, [sp, #0x20]
    ldp x2, x3, [sp, #0x10]
    ldp x0, x1, [sp, #0x00]
    add sp, sp, #0x120
    ldr x9, [x24, #0x60]!
    adrp x17, _WechatBridgeReq2BufEnterContinue@PAGE
    ldr x17, [x17, _WechatBridgeReq2BufEnterContinue@PAGEOFF]
    br x17

.globl _WechatBridgeReq2BufExitHook
_WechatBridgeReq2BufExitHook:
    sub sp, sp, #0x120
    stp x0, x1, [sp, #0x00]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    stp x8, x9, [sp, #0x40]
    stp x10, x11, [sp, #0x50]
    stp x12, x13, [sp, #0x60]
    stp x14, x15, [sp, #0x70]
    stp x16, x17, [sp, #0x80]
    str x30, [sp, #0x90]
    stp q0, q1, [sp, #0xa0]
    stp q2, q3, [sp, #0xc0]
    stp q4, q5, [sp, #0xe0]
    stp q6, q7, [sp, #0x100]
    mov x0, x25
    bl _WechatBridgeHandleReq2BufExit
    ldp q6, q7, [sp, #0x100]
    ldp q4, q5, [sp, #0xe0]
    ldp q2, q3, [sp, #0xc0]
    ldp q0, q1, [sp, #0xa0]
    ldr x30, [sp, #0x90]
    ldp x16, x17, [sp, #0x80]
    ldp x14, x15, [sp, #0x70]
    ldp x12, x13, [sp, #0x60]
    ldp x10, x11, [sp, #0x50]
    ldp x8, x9, [sp, #0x40]
    ldp x6, x7, [sp, #0x30]
    ldp x4, x5, [sp, #0x20]
    ldp x2, x3, [sp, #0x10]
    ldp x0, x1, [sp, #0x00]
    add sp, sp, #0x120
    ldp x28, x27, [sp], #0x60
    adrp x17, _WechatBridgeReq2BufExitContinue@PAGE
    ldr x17, [x17, _WechatBridgeReq2BufExitContinue@PAGEOFF]
    br x17
