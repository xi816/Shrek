section .text
global _start

_start:
  push rbp
  mov rbp, rsp
  sub rsp, 0x1

  push 4
  push s0
  mov rax, 0x1
  mov rdi, 0x1
  pop rsi
  pop rdx
  syscall

section .data
  s0: db 0x36,0x39,0x21,0xA,0x0
