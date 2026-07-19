# Custom Virtualizer VM Instruction Formats and Constants
from enum import IntEnum

class VMOpcode(IntEnum):
    VM_NOP = 0
    VM_ADD = 1
    VM_SUB = 2
    VM_LDR = 3
    VM_STR = 4
    VM_MOV = 5
    VM_CMP = 6
    VM_B = 7
    VM_B_EQ = 8
    VM_B_NE = 9
    VM_B_GT = 10
    VM_B_LT = 11
    VM_CBZ = 12
    VM_CBNZ = 13
    VM_BL = 14
    VM_RET = 15
    VM_HALT = 16
    VM_B_LE = 17
    VM_B_GE = 18
    VM_LSL = 19
    VM_LSR = 20
