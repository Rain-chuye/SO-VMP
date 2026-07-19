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
    VM_HALT = 16,
    VM_B_LE = 17,
    VM_B_GE = 18,
    VM_LSL = 19,
    VM_LSR = 20
} vm_opcode_t;

typedef struct {
    uint32_t op;
    uint32_t size; // 4 for 32-bit (w-regs), 8 for 64-bit (x-regs)
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
        uint64_t current_pc = ctx->pc;
        vm_insn_t insn = code[ctx->pc++];

        printf("[VM_DBG] PC: %02llu | OP: %d | Size: %d | Op1: %llu, Op2: %llu, Op3: %llu\n",
               (unsigned long long)current_pc, insn.op, insn.size,
               (unsigned long long)insn.op1, (unsigned long long)insn.op2, (unsigned long long)insn.op3);

        switch (insn.op) {
            case VM_NOP:
                break;
            case VM_ADD: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                // Handle 32-bit vs 64-bit addition sizing
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)(val2 + val3);
                } else {
                    ctx->regs[insn.op1] = val2 + val3;
                }
                printf("[VM_DBG]   ADD output reg[%llu] = %lld\n", (unsigned long long)insn.op1, (long long)ctx->regs[insn.op1]);
                break;
            }
            case VM_SUB: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                // Handle 32-bit vs 64-bit subtraction sizing
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)(val2 - val3);
                } else {
                    ctx->regs[insn.op1] = val2 - val3;
                }
                printf("[VM_DBG]   SUB output reg[%llu] = %lld\n", (unsigned long long)insn.op1, (long long)ctx->regs[insn.op1]);
                break;
            }
            case VM_MOV: {
                uint64_t val = (insn.op3 == 1) ? insn.op2 : ctx->regs[insn.op2];
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)val;
                } else {
                    ctx->regs[insn.op1] = val;
                }
                printf("[VM_DBG]   MOV output reg[%llu] = %lld\n", (unsigned long long)insn.op1, (long long)ctx->regs[insn.op1]);
                break;
            }
            case VM_CMP: {
                uint64_t val1 = ctx->regs[insn.op1];
                uint64_t val2 = (insn.op3 == 1) ? insn.op2 : ctx->regs[insn.op2];

                if (insn.size == 4) {
                    int32_t diff = (int32_t)val1 - (int32_t)val2;
                    ctx->cpsr_z = (diff == 0) ? 1 : 0;
                    ctx->cpsr_n = (diff < 0) ? 1 : 0;
                } else {
                    int64_t diff = (int64_t)val1 - (int64_t)val2;
                    ctx->cpsr_z = (diff == 0) ? 1 : 0;
                    ctx->cpsr_n = (diff < 0) ? 1 : 0;
                }
                printf("[VM_DBG]   CMP output CPSR_Z=%d, CPSR_N=%d\n", ctx->cpsr_z, ctx->cpsr_n);
                break;
            }
            case VM_LDR: {
                uint64_t addr = ctx->regs[insn.op2] + insn.op3;
                printf("[VM_DBG]   LDR from address: %p (Base: %p, Offset: %lld)\n", (void*)addr, (void*)ctx->regs[insn.op2], (long long)insn.op3);
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = *(uint32_t*)addr;
                } else {
                    ctx->regs[insn.op1] = *(uint64_t*)addr;
                }
                printf("[VM_DBG]   LDR output reg[%llu] = %lld\n", (unsigned long long)insn.op1, (long long)ctx->regs[insn.op1]);
                break;
            }
            case VM_STR: {
                uint64_t addr = ctx->regs[insn.op2] + insn.op3;
                printf("[VM_DBG]   STR to address: %p (Base: %p, Offset: %lld)\n", (void*)addr, (void*)ctx->regs[insn.op2], (long long)insn.op3);
                if (insn.size == 4) {
                    *(uint32_t*)addr = (uint32_t)ctx->regs[insn.op1];
                } else {
                    *(uint64_t*)addr = ctx->regs[insn.op1];
                }
                break;
            }
            case VM_B: {
                ctx->pc = insn.op1;
                printf("[VM_DBG]   B jumped PC to %llu\n", (unsigned long long)ctx->pc);
                break;
            }
            case VM_B_EQ: {
                if (ctx->cpsr_z == 1) {
                    ctx->pc = insn.op1;
                    printf("[VM_DBG]   B_EQ jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_B_NE: {
                if (ctx->cpsr_z == 0) {
                    ctx->pc = insn.op1;
                    printf("[VM_DBG]   B_NE jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_B_GT: {
                if (ctx->cpsr_z == 0 && ctx->cpsr_n == 0) {
                    ctx->pc = insn.op1;
                    printf("[VM_DBG]   B_GT jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_B_LT: {
                if (ctx->cpsr_n == 1) {
                    ctx->pc = insn.op1;
                    printf("[VM_DBG]   B_LT jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_B_LE: {
                if (ctx->cpsr_z == 1 || ctx->cpsr_n == 1) {
                    ctx->pc = insn.op1;
                    printf("[VM_DBG]   B_LE jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_B_GE: {
                if (ctx->cpsr_n == 0) {
                    ctx->pc = insn.op1;
                    printf("[VM_DBG]   B_GE jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_LSL: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)(val2 << val3);
                } else {
                    ctx->regs[insn.op1] = val2 << val3;
                }
                printf("[VM_DBG]   LSL output reg[%llu] = %lld\n", (unsigned long long)insn.op1, (long long)ctx->regs[insn.op1]);
                break;
            }
            case VM_LSR: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)(val2 >> val3);
                } else {
                    ctx->regs[insn.op1] = val2 >> val3;
                }
                printf("[VM_DBG]   LSR output reg[%llu] = %lld\n", (unsigned long long)insn.op1, (long long)ctx->regs[insn.op1]);
                break;
            }
            case VM_CBZ: {
                if (ctx->regs[insn.op1] == 0) {
                    ctx->pc = insn.op2;
                    printf("[VM_DBG]   CBZ jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_CBNZ: {
                if (ctx->regs[insn.op1] != 0) {
                    ctx->pc = insn.op2;
                    printf("[VM_DBG]   CBNZ jumped PC to %llu\n", (unsigned long long)ctx->pc);
                }
                break;
            }
            case VM_BL: {
                ctx->regs[30] = ctx->pc; // LR holds return IP index
                ctx->pc = insn.op1;
                printf("[VM_DBG]   BL jumped PC to %llu (saved LR=%llu)\n", (unsigned long long)ctx->pc, (unsigned long long)ctx->regs[30]);
                break;
            }
            case VM_RET: {
                ctx->pc = ctx->regs[insn.op1]; // typically lr (30)
                printf("[VM_DBG]   RET returned PC to %llu\n", (unsigned long long)ctx->pc);
                return; // Return from VM Execution
            }
            case VM_HALT:
            default:
                printf("[VM_DBG]   HALT!\n");
                return;
        }
    }
}
