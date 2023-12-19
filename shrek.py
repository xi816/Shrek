#!/usr/bin/python3

import os
import sys
import subprocess

from enum import Enum, auto
from colorama import Fore, Back
from dataclasses import dataclass

class TokenType(Enum):
  OP_INT_LIT     = auto()
  OP_STR_LIT     = auto()
  OP_IDENT       = auto()
  OP_PLUS        = auto() # +
  OP_PUTC        = auto() # putc
  OP_PUTS        = auto() # puts
  OP_DUP         = auto() # dup
  OP_DROP        = auto() # drop
  OP_SWAP        = auto() # swap
  OP_PROC_OPEN   = auto() # proc
  OP_DO          = auto() # do
  OP_TYPESET     = auto() # ::
  OP_TYPEOUT     = auto() # ->
  OP_END         = auto() # end
  OP_INCLUDE     = auto() # include
  OP_EXIT        = auto() # exit
  OP_TYPE_INT    = auto() # Int
  OP_TYPE_PTR    = auto() # Ptr
  OP_TYPE_BOOL   = auto() # Bool
  EOF            = auto()

class KType(Enum):
  INT    = auto()
  PTR    = auto()
  BOOL   = auto()

@dataclass
class Token:
  TYPE: TokenType # token.type  => <instance TokenType>
  VALUE: str      # token.value => String
  LOC: tuple      # token.loc   => (filename, column, row)

@dataclass
class Procedure:
  INS: list
  OUTS: list

revdict = lambda d: {v: k for k, v in d.items()}

def main(argc: int, argv: list) -> int:
  flags = parse_flags(argv[1:])
  if (flags["flagdump"]):
    compiler_warning("", flags.items())

  with open(flags["file"], "r") as fl:
    src = fl.read()
  tokens = lex_code_to_tokens(flags["file"], src)
  if (flags["tokendump"]):
    compiler_warning("", tokens)

  static_type_check(tokens, flags["typesdump"])
  if (flags["type"] == "nasmLinux64"):
    asmCode = generate_nasmLinux64(tokens, flags["file"])
  elif (flags["type"] == "nasmLinux32"):
    asmCode = generate_nasmLinux32(tokens, flags["file"])
  else:
    compiler_error("Uncreachable")

  file_no_ext = ".".join(flags["file"].split(".")[:-1])
  with open(f"{file_no_ext}.asm", "w") as fl:
    fl.write(asmCode)
  if (flags["asmdump"]):
    compiler_warning("", ["\n"+asmCode])

  subprocess.call(["nasm", "-felf64", f"{file_no_ext}.asm", "-o", f"{file_no_ext}.o"])
  subprocess.call(["ld", f"{file_no_ext}.o", "-o", f"{file_no_ext}"])

  exit_code = 0
  if (flags["autorun"]):
    exit_code = subprocess.call([f"./{file_no_ext}"])

  exit(exit_code)

def usage() -> None:
  print("USAGE of the Shrek Programming Language compiler:")
  print("  shrek (FLAG VALUE?)+ file.shrek")
  print("    Flags:")
  print("      -t, --type         Compilation type, can be `nasmLinux64` or `nasmLinux32`")
  print("      -r, --run          Run the program automatically after compiling")


def compiler_error(msg: str, notes: list = []) -> None:
  print(f"{Fore.RED}COMPILATION ERROR{Fore.RESET}: {msg}")
  if (notes):
    for el in notes:
      print(f"{Fore.GREEN}NOTE{Fore.RESET}: {el}")
  print()
  exit(1)

def compiler_warning(msg: str, notes: list = []) -> None:
  print(f"{Fore.YELLOW}COMPILATION WARNING{Fore.RESET}: {msg}")
  if (notes):
    for el in notes:
      print(f"{Fore.GREEN}NOTE{Fore.RESET}: {el}")
  print()

def compiler_note(msg: str, notes: list = []) -> None:
  print(f"{Fore.GREEN}COMPILATION NOTE{Fore.RESET}: {msg}")
  if (notes):
    for el in notes:
      print(f"{Fore.GREEN}NOTE{Fore.RESET}: {el}")
  print()

def parse_flags(flags: list) -> dict:
  dflags = {
    "type": "",
    "file": "",
    "autorun": False,
    "asmdump": False,
    "tokendump": False,
    "flagdump": False,
    "typesdump": False
  }
  p = 0
  while (flags[p] != "-f"):
    if (flags[p] == "-t"):
      p += 1
      if (flags[p] not in ("nasmLinux32", "nasmLinux64")):
        compiler_error(f"Unknown compilation type `{flags[p]}`", notes=["Maybe you meant `nasmLinux32` or `nasmLinux64`?"])
      dflags["type"] = flags[p]
    elif (flags[p] == "-r"):
      dflags["autorun"] = True
    elif (flags[p][:2] == "-D"):
      for i in flags[p][2:]:
        if (i == "t"):
          dflags["tokendump"] = True
        elif (i == "a"):
          dflags["asmdump"] = True
        elif (i == "f"):
          dflags["flagdump"] = True
        elif (i == "s"):
          dflags["typesdump"] = True
        elif (i == "*"):
          dflags["tokendump"] = True
          dflags["asmdump"] = True
          dflags["flagdump"] = True
          dflags["typesdump"] = True
        else:
          compiler_error(f"Unknown subflag `{i}` in flag `{flags[p]}`")
    else:
      compiler_error(f"Unkown flag `{flags[p]}`")
    p += 1
  dflags["file"] = flags[p+1]

  return dflags
  # assert False, "ERROR from parse_flags: parse_flags is not implemented yet"

def lex_code_to_tokens(filename: str, code: str) -> list:
  code += "\0"
  pos = 0
  ip_info = [1, 1]

  buf = ""
  tokens = []

  DIGITS = "0123456789"
  WHITESPACES = " \n"
  KEYWORDS = [
    "+", "dup", "drop", "swap", "putc", "puts", "exit",
    "proc", "do", "end", "include",
    "Int", "Ptr", "Bool", "::", "->"
  ]

  while (code[pos] != "\0"):
    if (code[pos] == "#"):
      while (code[pos] != "\n"):
        pos += 1
    elif (code[pos] == "\t"):
      compiler_warning(f"{filename}:{ip_info[0]}:{ip_info[1]}: Found tab (\\t) indentation symbol. Please use spaces instead of tabs, but it is not nessecary.")
      pos += 1
    elif (code[pos] in DIGITS):
      while (code[pos] in DIGITS):
        buf += code[pos]
        pos += 1
      tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=int(buf), LOC=(filename,)+tuple(ip_info)))
      buf = ""
    elif (code[pos] in WHITESPACES):
      pos += 1
    elif (code[pos] == "\""):
      pos += 1
      while (code[pos] != "\""):
        if (code[pos] != "\\"):
          buf += code[pos]
          pos += 1
        else:
          pos += 1
          if (code[pos] == 0):
            buf += "\0"
          elif (ord(code[pos]) in range(65, 91)):
            buf += chr(ord(code[pos])-64)
          else:
            compiler_error(f"\\{code[pos]} is unknown backslash escape")
          pos += 1
      tokens.append(Token(TYPE=TokenType.OP_STR_LIT, VALUE=buf, LOC=(filename,)+tuple(ip_info)))
      buf = ""
      pos += 1
    elif (code[pos] == "'"):
      pos += 1
      if (code[pos] != "\\"):
        if (code[pos+1] != "'"):
          compiler_error(f"{filename}:{ip_info[0]}:{ip_info[1]}: Unterminated character literal")
        tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=ord(code[pos]), LOC=(filename,)+tuple(ip_info)))
        pos += 2
      else:
        pos += 1
        while (code[pos] != "'"):
          buf += code[pos]
          pos += 1
        if (buf == "0"):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (ord(buf) in range(65, 91)):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=ord(buf)-64, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "["):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=27, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "]"):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=28, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "*"):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=29, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "_"):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=30, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "="):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=31, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "\\"):
          tokens.append(Token(TYPE=TokenType.OP_INT_LIT, VALUE=92, LOC=(filename,)+tuple(ip_info)))
        buf = ""
        pos += 1
    else:
      while (code[pos] not in WHITESPACES):
        buf += code[pos]
        pos += 1
      if (buf in KEYWORDS):
        if (buf == "exit"):
          tokens.append(Token(TYPE=TokenType.OP_EXIT, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "+"):
          tokens.append(Token(TYPE=TokenType.OP_PLUS, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "putc"):
          tokens.append(Token(TYPE=TokenType.OP_PUTC, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "puts"):
          tokens.append(Token(TYPE=TokenType.OP_PUTS, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "dup"):
          tokens.append(Token(TYPE=TokenType.OP_DUP, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "drop"):
          tokens.append(Token(TYPE=TokenType.OP_DROP, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "swap"):
          tokens.append(Token(TYPE=TokenType.OP_SWAP, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "proc"):
          tokens.append(Token(TYPE=TokenType.OP_PROC_OPEN, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "do"):
          tokens.append(Token(TYPE=TokenType.OP_DO, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "end"):
          tokens.append(Token(TYPE=TokenType.OP_END, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "include"):
          tokens.append(Token(TYPE=TokenType.OP_INCLUDE, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "Int"):
          tokens.append(Token(TYPE=TokenType.OP_TYPE_INT, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "Ptr"):
          tokens.append(Token(TYPE=TokenType.OP_TYPE_PTR, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "Bool"):
          tokens.append(Token(TYPE=TokenType.OP_TYPE_BOOL, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "::"):
          tokens.append(Token(TYPE=TokenType.OP_TYPESET, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        elif (buf == "->"):
          tokens.append(Token(TYPE=TokenType.OP_TYPEOUT, VALUE=0, LOC=(filename,)+tuple(ip_info)))
        else:
          compiler_error(f"Keyword `{buf}` is not handling right now.")
      else:
        tokens.append(Token(TYPE=TokenType.OP_IDENT, VALUE=buf, LOC=(filename,)+tuple(ip_info)))
      buf = ""
  tokens.append(Token(TYPE=TokenType.EOF, VALUE=0, LOC=(filename,)+tuple(ip_info)))
  return tokens
  # compiler_error("lex_code_to_tokens is not implemented yet")

def peek_types(stack: list, types: list, fc: str) -> None:
  # types.reverse()
  actual_types = []
  for i in stack[-len(types):]:
    actual_types.append(i)
  if (actual_types != stack[-len(types):]):
    compiler_error(f"Type checking failed because function `{fc}` expected types `{types}`, but got types {actual_types}")

def static_type_check(program: list, debug: bool) -> int:
  metaStack = []
  ip = 0

  procedures = {}

  while (program[ip].TYPE != TokenType.EOF):
    if (debug):
      compiler_note(f"Debugging the current type checker stack: {metaStack}", notes=[f"The current instuction is {program[ip]}"])

    if (program[ip].TYPE == TokenType.OP_EXIT):
      break
    elif (program[ip].TYPE == TokenType.OP_INT_LIT):
      metaStack.append(KType.INT)
    elif (program[ip].TYPE == TokenType.OP_STR_LIT):
      metaStack.append(KType.INT)
      metaStack.append(KType.PTR)
    elif (program[ip].TYPE == TokenType.OP_INCLUDE):
      ip += 1
    elif (program[ip].TYPE == TokenType.OP_PLUS):
      peek_types(metaStack, [KType.INT, KType.INT], "+")
      metaStack.pop()
    elif (program[ip].TYPE == TokenType.OP_PUTC):
      peek_types(metaStack, [KType.INT], "putc")
      metaStack.pop()
    elif (program[ip].TYPE == TokenType.OP_DUP):
      metaStack.append(metaStack[-1])
    elif (program[ip].TYPE == TokenType.OP_SWAP):
      metaStack[-2], metaStack[-1] = metaStack[-1], metaStack[-2]
    elif (program[ip].TYPE == TokenType.OP_DROP):
      if (len(metaStack) < 1):
        compiler_error("Error: trying to use the `drop` function when the stack is empty")
      metaStack.pop()
    elif (program[ip].TYPE == TokenType.OP_PROC_OPEN):
      ip += 1
      if (program[ip].TYPE != TokenType.OP_IDENT):
        compiler_error(f"Error in procedure definition. `proc <name>` expected to be an identifier, but found {program[ip].TYPE}")
      current_proc_name = program[ip].VALUE
      procedures[current_proc_name] = Procedure(INS=[], OUTS=[])
      ip += 2
      if (program[ip].TYPE == TokenType.OP_TYPEOUT):
        compiler_error("Error. Syntax `:: -> OutTypes do` is used in procedure definition. If you want the procedure don't use output parameters, just write `:: OutTypes do`")
      if (program[ip-1].TYPE == TokenType.OP_TYPESET):
        while (program[ip].TYPE != TokenType.OP_TYPEOUT):
          if (program[ip].TYPE == TokenType.OP_DO):
            procedures[current_proc_name].OUTS = procedures[current_proc_name].INS
            procedures[current_proc_name].INS = []
            break
          if (program[ip].TYPE not in [TokenType.OP_TYPE_INT, TokenType.OP_TYPE_PTR, TokenType.OP_TYPE_BOOL]):
            compiler_error(f"Error at procedure definition. Unxecpected {program[ip].TYPE} when parsing the procedure input types")
          procedures[current_proc_name].INS.append(program[ip].TYPE)
          ip += 1
        ip += 1
        if (not procedures[current_proc_name].OUTS):
          while (program[ip].TYPE != TokenType.OP_DO):
            if (program[ip].TYPE not in [TokenType.OP_TYPE_INT, TokenType.OP_TYPE_PTR, TokenType.OP_TYPE_BOOL]):
              compiler_error(f"Error at procedure definition. Unxecpected {program[ip].TYPE} when parsing the procedure input types")
            procedures[current_proc_name].INS.append(program[ip].TYPE)
            ip += 1
          compiler_error(procedures[current_proc_name])
    elif (program[ip].TYPE == TokenType.OP_PUTS):
      peek_types(metaStack, [KType.INT, KType.PTR], "puts")
      metaStack.pop()
      metaStack.pop()
    else:
      compiler_error(f"{program[ip].TYPE} is not handling right now.")
    ip += 1
  if (debug):
    compiler_note(f"Debugging the current type checker stack: {metaStack}", notes=[f"The current instuction is {program[ip]}"])
  if (metaStack):
    compiler_error("Unhandled data on the stack after the end of a program", notes=[f"The unhandled data is: {metaStack}"])

  return 0


def generate_nasmLinux32(program: list, filename: str) -> str:
  compiler_error("generate_nasmLinux32 is not implemented yet")
  return 1

def generate_nasmLinux64(program: list, filename: str) -> str:
  ip = 0
  op_flags = [False, False, False, False, False, False, False, False]
  asmCode = "section .text\nglobal _start\n\n_start:\n  push rbp\n  mov rbp, rsp\n  sub rsp, 0x1\n\n"
  asmCodeThen = ["\nsection .data\n"]

  string_literals = {}
  strlits_count = 0

  while (program[ip].TYPE != TokenType.EOF):
    if (program[ip].TYPE == TokenType.OP_INT_LIT):
      asmCode += f"  mov rax, {hex(program[ip].VALUE)}\n  push rax\n"
      ip += 1
    elif (program[ip].TYPE == TokenType.OP_STR_LIT):
      if (program[ip].VALUE not in list(string_literals.values())):
        string_literals[strlits_count] = program[ip].VALUE
        asmCode += f"  push {len(program[ip].VALUE)}\n  push s{revdict(string_literals)[program[ip].VALUE]}\n"
        asmCodeThen[0] += f"  s{strlits_count}: db {','.join(map(lambda x: '0x'+str(hex(ord(x)))[2:].upper(), program[ip].VALUE+chr(0)))}\n"
        strlits_count += 1
        ip += 1
      else:
        asmCode += f"  push {len(program[ip].VALUE)}\n  push s{revdict(string_literals)[program[ip].VALUE]}\n"
        ip += 1
    elif (program[ip].TYPE == TokenType.OP_PLUS):
      asmCode += "  pop rax\n  pop rbx\n  add rax, rbx\n  push rax\n"
      ip += 1
      op_flags[0] = False
    elif (program[ip].TYPE == TokenType.OP_PUTC):
      if (op_flags[0] == True):
        asmCode += f"  pop rax\n  mov BYTE [rsp-1], al\n  mov rax, 0x1\n  syscall\n"
      else:
        asmCode += f"  pop rax\n  mov BYTE [rsp-1], al\n  mov rax, 0x1\n  mov rdi, 0x1\n  mov rsi, rsp\n  sub rsi, 1\n  mov rdx, 0x1\n  syscall\n"
      ip += 1
      op_flags[0] = True
    elif (program[ip].TYPE == TokenType.OP_PUTS):
      if (op_flags[0] == True):
        asmCode += f"  mov rax, 0x1\n  pop rsi\n  pop rdx\n  syscall\n"
      else:
        asmCode += f"  mov rax, 0x1\n  mov rdi, 0x1\n  pop rsi\n  pop rdx\n  syscall\n"
      ip += 1
    elif (program[ip].TYPE == TokenType.OP_DUP):
      asmCode += f"  pop rax\n  push rax\n  push rax\n"
      ip += 1
      op_flags[0] = False
    elif (program[ip].TYPE == TokenType.OP_DROP):
      asmCode += f"  pop rax\n"
      ip += 1
      op_flags[0] = False
    elif (program[ip].TYPE == TokenType.OP_SWAP):
      asmCode += f"  pop rax\n  pop rbx\n  push rax\n  push rbx\n"
      ip += 1
      op_flags[0] = False
    elif (program[ip].TYPE == TokenType.OP_INCLUDE):
      if (program[ip+1].TYPE != TokenType.OP_STR_LIT):
        compiler_error(f"The `include` statement requires the string as a file name, but got {program[ip+1].TYPE}")
      try:
        with open("/".join(filename.split("/")[:-1])+"/"+program[ip+1].VALUE, "r") as fl:
          tks = lex_code_to_tokens("/".join(filename.split("/")[:-1])+"/"+program[ip+1].VALUE, fl.read())
          tks.reverse()
          program.pop(ip)
          program.pop(ip)
          for t in tks:
            program.insert(ip, t)
      except FileNotFoundError:
        compiler_error(f"File {program[ip+1].VALUE} was not found")
    elif (program[ip].TYPE == TokenType.OP_EXIT):
      asmCode += "  mov rax, 0x3C\n  pop rdi\n  syscall\n"
      ip += 1
      op_flags[0] = False
    else:
      compiler_error(f"Keyword {program[ip].TYPE} was not handled")

  for snp in asmCodeThen:
    asmCode += snp
  return asmCode
  # compiler_error("generate_nasmLinux64 is not implemented yet")

if (__name__ == "__main__"):
  main(len(sys.argv), sys.argv)

