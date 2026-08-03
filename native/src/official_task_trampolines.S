.text
.p2align 2

.globl _WechatBridgeInvokeOfficialTaskBuilder
_WechatBridgeInvokeOfficialTaskBuilder:
    mov x9, x0
    mov x8, x1
    mov x0, x2
    mov x1, x3
    mov w2, w4
    br x9

.globl _WechatBridgeInvokeOfficialTaskSubmit
_WechatBridgeInvokeOfficialTaskSubmit:
    mov x9, x0
    mov x8, x1
    mov x0, x2
    mov x1, x3
    mov x2, x4
    mov x3, x5
    mov x4, x6
    br x9
