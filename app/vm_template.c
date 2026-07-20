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
#include <dlfcn.h>

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
    uint64_t pointer_xor_key; // XOR Key for lua_State* pointer obfuscation
    uint64_t vm_stack_ptr;    // Stack pointer for stack-based execution
    uint64_t vm_stack_mem[512]; // Internal Stack-based VM memory
} vm_context_t;

// Dynamic rolling XOR decryption for bytecode arrays
void decrypt_bytecode(uint8_t *encrypted, uint8_t *decrypted, uint32_t size, uint8_t key) {
    uint8_t current_key = key;
    for (uint32_t i = 0; i < size; i++) {
        decrypted[i] = encrypted[i] ^ current_key;
        current_key = current_key + decrypted[i] + i; // rolling key based on ciphertext/plaintext
    }
}

// Find the loaded base address of libprotected.so contiguously in memory maps safely
void* find_self_base_address() {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return NULL;

    char line[512];
    uintptr_t base_addr = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libprotected.so")) {
            // Parse starting hex address of first PT_LOAD segment of libprotected.so
            if (sscanf(line, "%lx-", &base_addr) == 1) {
                break;
            }
        }
    }
    fclose(maps);
    return (void*)base_addr;
}

// In-Memory ELF Header zeroing to prevent runtime Memory Dump
void anti_dump_zero_elf_header() {
    void* base_addr = find_self_base_address();
    if (!base_addr) return;

    long page_size = sysconf(_SC_PAGESIZE);
    void* page_start = (void*)((uintptr_t)base_addr & ~(page_size - 1));

    // Set page to writable AND executable to allow dynamic zeroing without execution fault
    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        memset(base_addr, 0, 64); // Overwrite first 64 bytes of ELF Header
        mprotect(page_start, page_size, PROT_READ | PROT_EXEC); // Restore protection
        printf("[VM Guardian] Anti-Dump: In-memory ELF header successfully zeroed out!\n");
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
            // Check for typical Frida or substrate hook names (exclude libprotected.so itself!)
            if (!strstr(line, "libprotected.so") && (strstr(line, "frida") || strstr(line, "gum-js") || strstr(line, "libfrida"))) {
                printf("[VM Guardian] Security Violation: Hooking frame detected in memory maps!\n");
                fclose(maps);
                return 1;
            }
        }
        fclose(maps);
    }

    return 0; // Security check passed
}
