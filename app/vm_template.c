#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

// JNI Types and Structs for libluajava.so dynamic JNI registration support
typedef void* JNIEnv;
typedef void* jobject;
typedef void* jclass;
typedef void* jstring;
typedef int jint;
typedef void* JavaVM;

typedef struct {
    const char* name;
    const char* signature;
    void*       fnPtr;
} JNINativeMethod;

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

// Dynamic rolling XOR decryption for bytecode arrays
void decrypt_bytecode(uint8_t *encrypted, uint8_t *decrypted, uint32_t size, uint8_t key) {
    uint8_t current_key = key;
    for (uint32_t i = 0; i < size; i++) {
        decrypted[i] = encrypted[i] ^ current_key;
        current_key = current_key + decrypted[i] + i; // rolling key based on ciphertext/plaintext
    }
}

// Multi-layered Anti-Debugger and Hooking checks
int perform_security_checks() {
    // 1. Ptrace Traceme - Returns -1 if debugger is already attached
    #ifndef PTRACE_TRACEME
    #define PTRACE_TRACEME 0
    #endif
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        if (errno != ENOSYS) {
            printf("[VM Guardian] Anti-Debug Active: Ptrace attachment detected!\n");
            return 1;
        }
    }

    // 2. TracerPid Scan from /proc/self/status
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[128];
        int tracer_pid = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tracer_pid = atoi(&line[10]);
                break;
            }
        }
        fclose(f);
        if (tracer_pid != 0) {
            printf("[VM Guardian] Anti-Debug Active: TracerPid = %d detected!\n", tracer_pid);
            return 1;
        }
    }

    // 3. Scan memory maps for Frida / Hooking frameworks
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            // Check for typical Frida or substrate hook names
            if (strstr(line, "frida") || strstr(line, "gum-js") || strstr(line, "libfrida")) {
                printf("[VM Guardian] Security Violation: Hooking frame detected in memory maps!\n");
                fclose(maps);
                return 1;
            }
        }
        fclose(maps);
    }

    return 0; // Security check passed
}

// VM Executor core loop
void vm_execute(vm_insn_t *code, uint32_t num_instructions, vm_context_t *ctx) {
    // Timing-based Anti-Debug setup
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);
    uint32_t executed_instructions = 0;

    while (ctx->pc < num_instructions) {
        uint64_t current_pc = ctx->pc;
        vm_insn_t insn = code[ctx->pc++];
        executed_instructions++;

        // Debug output (comment out or keep for testing)
        printf("[VM_DBG] PC: %02llu | OP: %d | Size: %d | Op1: %llu, Op2: %llu, Op3: %llu\n",
               (unsigned long long)current_pc, insn.op, insn.size,
               (unsigned long long)insn.op1, (unsigned long long)insn.op2, (unsigned long long)insn.op3);

        switch (insn.op) {
            case VM_NOP:
                break;
            case VM_ADD: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)(val2 + val3);
                } else {
                    ctx->regs[insn.op1] = val2 + val3;
                }
                break;
            }
            case VM_SUB: {
                uint64_t val2 = ctx->regs[insn.op2];
                uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)(val2 - val3);
                } else {
                    ctx->regs[insn.op1] = val2 - val3;
                }
                break;
            }
            case VM_MOV: {
                uint64_t val = (insn.op3 == 1) ? insn.op2 : ctx->regs[insn.op2];
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = (uint32_t)val;
                } else {
                    ctx->regs[insn.op1] = val;
                }
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
                break;
            }
            case VM_LDR: {
                uint64_t addr = ctx->regs[insn.op2] + insn.op3;
                if (insn.size == 4) {
                    ctx->regs[insn.op1] = *(uint32_t*)addr;
                } else {
                    ctx->regs[insn.op1] = *(uint64_t*)addr;
                }
                break;
            }
            case VM_STR: {
                uint64_t addr = ctx->regs[insn.op2] + insn.op3;
                if (insn.size == 4) {
                    *(uint32_t*)addr = (uint32_t)ctx->regs[insn.op1];
                } else {
                    *(uint64_t*)addr = ctx->regs[insn.op1];
                }
                break;
            }
            case VM_B: {
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
            case VM_B_LE: {
                if (ctx->cpsr_z == 1 || ctx->cpsr_n == 1) {
                    ctx->pc = insn.op1;
                }
                break;
            }
            case VM_B_GE: {
                if (ctx->cpsr_n == 0) {
                    ctx->pc = insn.op1;
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

    // 4. Timing-based Anti-Debug validation
    gettimeofday(&end_time, NULL);
    double elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 + (end_time.tv_usec - start_time.tv_usec) / 1000.0;
    // If average execution time per VM instruction is > 5ms, a debugger is likely tracing / stepping!
    if (executed_instructions > 0 && (elapsed_ms / executed_instructions) > 5.0) {
        printf("[VM Guardian] Anti-Debug Active: High latency debug stepping detected!\n");
        abort();
    }
}
