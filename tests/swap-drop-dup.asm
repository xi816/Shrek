section .text
global _start

_start:
  push rbp
  mov rbp, rsp
  sub rsp, 0x1

  mov rax, 0x22
  push rax
  mov rax, 0x23
  push rax
  pop rax
  pop rbx
  add rax, rbx
  push rax
  mov rax, 0xc8
  push rax
  mov rax, 0xdc
  push rax
  pop rax
  pop rbx
  add rax, rbx
  push rax
  pop rax
  pop rbx
  push rax
  push rbx
  pop rax
  push rax
  push rax
  pop rax
  mov BYTE [rsp-1], al
  mov rax, 0x1
  mov rdi, 0x1
  mov rsi, rsp
  sub rsi, 1
  mov rdx, 0x1
  syscall
  pop rax
  pop rbx
  push rax
  push rbx
  pop rax
  pop rax
  mov rax, 0xa
  push rax
  pop rax
  mov BYTE [rsp-1], al
  mov rax, 0x1
  mov rdi, 0x1
  mov rsi, rsp
  sub rsi, 1
  mov rdx, 0x1
  syscall

section .data
