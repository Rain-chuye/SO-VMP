#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// VM Opcode Definitions (Must match Python's VMOpcode)
typedef enum {
    VM_NOP = 0,
    VM_ADD = 1,
    VM_SUB = 2,
    VM_LDR = 3,
    VM_STR = 4,
    VM_MOV = 5,
    VM_CMP = 6,
    VM_B = 7,
    VM_B_EQ = 8,
    VM_B_NE = 9,
    VM_B_GT = 10,
    VM_B_LT = 11,
    VM_CBZ = 12,
    VM_CBNZ = 13,
    VM_BL = 14,
    VM_RET = 15,
    VM_HALT = 16
} vm_opcode_t;

typedef struct {
    uint32_t op;
    uint64_t op1;
    uint64_t op2;
    uint64_t op3;
} vm_insn_t;

typedef struct {
    uint64_t regs[32]; // x0 - x31 (SP = regs[31])
    uint64_t pc;
    uint32_t cpsr_z; // Zero flag
    uint32_t cpsr_n; // Negative flag
    uint32_t cpsr_c; // Carry flag
    uint32_t cpsr_v; // Overflow flag
} vm_context_t;

// Standard Anti-Debugger checks
int detect_debugger() {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[128];
    int tracer_pid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(&line[10]);
            break;
        }
    }
    fclose(f);
    return tracer_pid != 0;
}

// VM Executor core loop
void vm_execute(vm_insn_t *code, uint32_t num_instructions, vm_context_t *ctx) {
    while (ctx->pc < num_instructions) {
        vm_insn_t insn = code[ctx->pc++];
        switch (insn.op) {
            case VM_NOP:
                break;
            case VM_ADD: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                ctx->regs[insn.op1] = val2 + val3;
                break;
            }
            case VM_SUB: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                ctx->regs[insn.op1] = val2 - val3;
                break;
            }
            case VM_MOV: {
                uint64_t val = (insn.op3 == 1) ? insn.op2 : ctx->regs[insn.op2];
                ctx->regs[insn.op1] = val;
                break;
            }
            case VM_CMP: {
                uint64_t val1 = ctx->regs[insn.op1];
                uint64_t val2 = (insn.op3 == 1) ? insn.op2 : ctx->regs[insn.op2];
                int64_t diff = (int64_t)val1 - (int64_t)val2;
                ctx->cpsr_z = (diff == 0) ? 1 : 0;
                ctx->cpsr_n = (diff < 0) ? 1 : 0;
                break;
            }
            case VM_LDR: {
                // op1: dest reg, op2: base reg, op3: offset
                uint64_t addr = ctx->regs[insn.op2] + insn.op3;
                ctx->regs[insn.op1] = *(uint64_t*)addr;
                break;
            }
            case VM_STR: {
                // op1: src reg, op2: base reg, op3: offset
                uint64_t addr = ctx->regs[insn.op2] + insn.op3;
                *(uint64_t*)addr = ctx->regs[insn.op1];
                break;
            }
            case VM_B: {
                // Simple relative or absolute PC jump (simplified to instruction indices here)
                ctx->pc = insn.op1;
                break;
            }
            case VM_B_EQ: {
                if (ctx->cpsr_z == 1) {
                    ctx->pc = insn.op1;
                }
                break;
            }
            case VM_B_NE: {
                if (ctx->cpsr_z == 0) {
                    ctx->pc = insn.op1;
                }
                break;
            }
            case VM_B_GT: {
                if (ctx->cpsr_z == 0 && ctx->cpsr_n == 0) {
                    ctx->pc = insn.op1;
                }
                break;
            }
            case VM_B_LT: {
                if (ctx->cpsr_n == 1) {
                    ctx->pc = insn.op1;
                }
                break;
            }
            case VM_CBZ: {
                if (ctx->regs[insn.op1] == 0) {
                    ctx->pc = insn.op2;
                }
                break;
            }
            case VM_CBNZ: {
                if (ctx->regs[insn.op1] != 0) {
                    ctx->pc = insn.op2;
                }
                break;
            }
            case VM_BL: {
                ctx->regs[30] = ctx->pc; // LR holds return IP index
                ctx->pc = insn.op1;
                break;
            }
            case VM_RET: {
                ctx->pc = ctx->regs[insn.op1]; // typically lr (30)
                return; // Return from VM Execution
            }
            case VM_HALT:
            default:
                return;
        }
    }
}
