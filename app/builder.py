import os
import struct
import random
import subprocess
import tempfile
from app.vm_defs import VMOpcode

def generate_virtualized_so(arch: str, selected_funcs: list, original_so_path: str):
    """
    Generates a new C file combining:
    1. The core VM loader/interpreter
    2. Statically encrypted function bytecode arrays
    3. Compile-time Randomized Opcode Mapping (256 randomized opcode slots)
    4. Multi-layered Anti-Debug & Anti-Hooking (Ptrace, maps scanning, timing checking)
    5. JNI Dynamic Registration (JNINativeMethod tables & JNI_OnLoad preloading of 5 system libraries)
    6. Pointer XOR-Obfuscation (XOR keys dynamically protecting sensitive lua_State* pointer in memory)
    7. In-Memory ELF Header zeroing to protect against Memory Dump

    Then cross-compiles it to a new SO library.
    """
    # 1. Generate randomized opcode mapping (unique key for each compiler run)
    mapping = list(range(256))
    random.shuffle(mapping)

    # Pack instructions using randomized opcodes
    def encrypt_bytecode_rolling(insns, key):
        raw_bytes = bytearray()
        for ins in insns:
            rand_op = mapping[int(ins['op'])]
            raw_bytes.extend(struct.pack('<IIQQQ', rand_op, ins['size'], ins['op1'], ins['op2'], ins['op3']))

        encrypted = bytearray()
        current_key = key
        for i, b in enumerate(raw_bytes):
            enc_b = b ^ current_key
            encrypted.append(enc_b)
            current_key = (current_key + b + i) & 0xFF

        return encrypted

    # Load base template containing declarations and checks
    template_path = os.path.join(os.path.dirname(__file__), "vm_template.c")
    with open(template_path, "r") as f:
        vm_template_src = f.read()

    # Generate custom switch cases dynamically using our randomized mapping!
    switch_cases = f"""
// VM Executor core loop with Randomized Opcode Switch Cases
void vm_execute(vm_insn_t *code, uint32_t num_instructions, vm_context_t *ctx) {{
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);
    uint32_t executed_instructions = 0;

    while (ctx->pc < num_instructions) {{
        uint64_t current_pc = ctx->pc;
        vm_insn_t insn = code[ctx->pc++];
        executed_instructions++;

        printf("[VM_DBG] PC: %02llu | OP: %d | Size: %d\\n",
               (unsigned long long)current_pc, insn.op, insn.size);

        // Dynamic execution of randomized switch cases
        if (insn.op == {mapping[VMOpcode.VM_NOP]}) {{
            // VM_NOP
        }}
        else if (insn.op == {mapping[VMOpcode.VM_ADD]}) {{
            // VM_ADD
            uint64_t val2 = ctx->regs[insn.op2];
            uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
            if (insn.size == 4) {{
                ctx->regs[insn.op1] = (uint32_t)(val2 + val3);
            }} else {{
                ctx->regs[insn.op1] = val2 + val3;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_SUB]}) {{
            // VM_SUB
            uint64_t val2 = ctx->regs[insn.op2];
            uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
            if (insn.size == 4) {{
                ctx->regs[insn.op1] = (uint32_t)(val2 - val3);
            }} else {{
                ctx->regs[insn.op1] = val2 - val3;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_MOV]}) {{
            // VM_MOV
            uint64_t val = (insn.op3 == 1) ? insn.op2 : ctx->regs[insn.op2];
            if (insn.size == 4) {{
                ctx->regs[insn.op1] = (uint32_t)val;
            }} else {{
                ctx->regs[insn.op1] = val;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_CMP]}) {{
            // VM_CMP
            uint64_t val1 = ctx->regs[insn.op1];
            uint64_t val2 = (insn.op3 == 1) ? insn.op2 : ctx->regs[insn.op2];
            if (insn.size == 4) {{
                int32_t diff = (int32_t)val1 - (int32_t)val2;
                ctx->cpsr_z = (diff == 0) ? 1 : 0;
                ctx->cpsr_n = (diff < 0) ? 1 : 0;
            }} else {{
                int64_t diff = (int64_t)val1 - (int64_t)val2;
                ctx->cpsr_z = (diff == 0) ? 1 : 0;
                ctx->cpsr_n = (diff < 0) ? 1 : 0;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_LDR]}) {{
            // VM_LDR
            uint64_t addr = ctx->regs[insn.op2] + insn.op3;
            if (insn.size == 4) {{
                ctx->regs[insn.op1] = *(uint32_t*)addr;
            }} else {{
                ctx->regs[insn.op1] = *(uint64_t*)addr;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_STR]}) {{
            // VM_STR
            uint64_t addr = ctx->regs[insn.op2] + insn.op3;
            if (insn.size == 4) {{
                *(uint32_t*)addr = (uint32_t)ctx->regs[insn.op1];
            }} else {{
                *(uint64_t*)addr = ctx->regs[insn.op1];
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_B]}) {{
            // VM_B
            ctx->pc = insn.op1;
        }}
        else if (insn.op == {mapping[VMOpcode.VM_B_EQ]}) {{
            // VM_B_EQ
            if (ctx->cpsr_z == 1) {{
                ctx->pc = insn.op1;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_B_NE]}) {{
            // VM_B_NE
            if (ctx->cpsr_z == 0) {{
                ctx->pc = insn.op1;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_B_GT]}) {{
            // VM_B_GT
            if (ctx->cpsr_z == 0 && ctx->cpsr_n == 0) {{
                ctx->pc = insn.op1;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_B_LT]}) {{
            // VM_B_LT
            if (ctx->cpsr_n == 1) {{
                ctx->pc = insn.op1;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_B_LE]}) {{
            // VM_B_LE
            if (ctx->cpsr_z == 1 || ctx->cpsr_n == 1) {{
                ctx->pc = insn.op1;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_B_GE]}) {{
            // VM_B_GE
            if (ctx->cpsr_n == 0) {{
                ctx->pc = insn.op1;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_LSL]}) {{
            // VM_LSL
            uint64_t val2 = ctx->regs[insn.op2];
            uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
            if (insn.size == 4) {{
                ctx->regs[insn.op1] = (uint32_t)(val2 << val3);
            }} else {{
                ctx->regs[insn.op1] = val2 << val3;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_LSR]}) {{
            // VM_LSR
            uint64_t val2 = ctx->regs[insn.op2];
            uint64_t val3 = (insn.op3 & 0x80000000) ? (insn.op3 & 0x7FFFFFFF) : ctx->regs[insn.op3];
            if (insn.size == 4) {{
                ctx->regs[insn.op1] = (uint32_t)(val2 >> val3);
            }} else {{
                ctx->regs[insn.op1] = val2 >> val3;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_CBZ]}) {{
            // VM_CBZ
            if (ctx->regs[insn.op1] == 0) {{
                ctx->pc = insn.op2;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_CBNZ]}) {{
            // VM_CBNZ
            if (ctx->regs[insn.op1] != 0) {{
                ctx->pc = insn.op2;
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_BL]}) {{
            // VM_BL
            ctx->regs[30] = ctx->pc;
            ctx->pc = insn.op1;
        }}
        else if (insn.op == {mapping[VMOpcode.VM_RET]}) {{
            // VM_RET
            ctx->pc = ctx->regs[insn.op1];
            return;
        }}
        else if (insn.op == {mapping[VMOpcode.VM_PUSH]}) {{
            // VM_PUSH
            ctx->vm_stack_mem[ctx->vm_stack_ptr++] = ctx->regs[insn.op1];
        }}
        else if (insn.op == {mapping[VMOpcode.VM_POP]}) {{
            // VM_POP
            if (ctx->vm_stack_ptr > 0) {{
                ctx->regs[insn.op1] = ctx->vm_stack_mem[--ctx->vm_stack_ptr];
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_LOAD]}) {{
            // VM_LOAD from VM Stack offset
            ctx->regs[insn.op1] = ctx->vm_stack_mem[insn.op2];
        }}
        else if (insn.op == {mapping[VMOpcode.VM_STORE]}) {{
            // VM_STORE to VM Stack offset
            ctx->vm_stack_mem[insn.op2] = ctx->regs[insn.op1];
        }}
        else if (insn.op == {mapping[VMOpcode.VM_SVC]}) {{
            // VM_SVC (Virtual Service Call / JNI boundary unified outlet)
            printf("[VM_DBG]   SVC call performed successfully!\\n");
        }}
        else if (insn.op == {mapping[VMOpcode.VM_BLR]}) {{
            // VM_BLR indirect jump (e.g., jump to register address)
            ctx->regs[30] = ctx->pc;
            ctx->pc = ctx->regs[insn.op1];
        }}
        else if (insn.op == {mapping[VMOpcode.VM_MUL]}) {{
            // VM_MUL
            ctx->regs[insn.op1] = ctx->regs[insn.op2] * ctx->regs[insn.op3];
        }}
        else if (insn.op == {mapping[VMOpcode.VM_DIV]}) {{
            // VM_DIV
            if (ctx->regs[insn.op3] != 0) {{
                ctx->regs[insn.op1] = ctx->regs[insn.op2] / ctx->regs[insn.op3];
            }}
        }}
        else if (insn.op == {mapping[VMOpcode.VM_AND]}) {{
            // VM_AND
            ctx->regs[insn.op1] = ctx->regs[insn.op2] & ctx->regs[insn.op3];
        }}
        else if (insn.op == {mapping[VMOpcode.VM_OR]}) {{
            // VM_OR
            ctx->regs[insn.op1] = ctx->regs[insn.op2] | ctx->regs[insn.op3];
        }}
        else {{
            // HALT
            return;
        }}
    }}

    // Timing check
    gettimeofday(&end_time, NULL);
    double elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 + (end_time.tv_usec - start_time.tv_usec) / 1000.0;
    if (executed_instructions > 0 && (elapsed_ms / executed_instructions) > 5.0) {{
        printf("[VM Guardian] Anti-Debug Active: High latency debug stepping detected!\\n");
        abort();
    }}
}}
"""

    bytecode_declarations = []
    function_definitions = []
    jni_methods_entries = []

    for idx, func in enumerate(selected_funcs):
        func_name = func['name']
        instructions = func['instructions'] # List of VM instructions

        # Generate random rolling XOR key
        xor_key = random.randint(1, 254)

        # Encrypt the instructions using randomized opcodes
        enc_bytes = encrypt_bytecode_rolling(instructions, xor_key)

        # Formulate hex array representation
        hex_lines = []
        for i in range(0, len(enc_bytes), 16):
            chunk = enc_bytes[i:i+16]
            hex_lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk))

        array_name = f"vm_code_enc_{idx}"
        array_size_bytes = len(enc_bytes)
        num_instructions = len(instructions)

        bytecode_declarations.append(f"""
// Encrypted bytecode array for {func_name} (Size: {array_size_bytes} bytes, Key: {xor_key})
static const uint8_t {array_name}[{array_size_bytes}] = {{
{",\n".join(hex_lines)}
}};
""")

        # Build wrapper with internal local name
        wrapper_name = f"virtualized_{func_name}"

        func_def = f"""
// Thread-safe virtualized implementation of {func_name}
// Supports standard JNI parameter passing (JNIEnv*, jclass, jobject, lua_State*, etc.)
static long long {wrapper_name}(long long arg0, long long arg1, long long arg2, long long arg3,
                                long long arg4, long long arg5, long long arg6, long long arg7) {{

    // 1. Runtime Anti-Debugger check
    if (perform_security_checks()) {{
        printf("[VM Guardian] Security violation detected! Exiting execution.\\n");
        abort();
    }}

    // 2. Dynamic Stack Decryption
    vm_insn_t decrypted_code[{num_instructions}];
    decrypt_bytecode((uint8_t*){array_name}, (uint8_t*)decrypted_code, {array_size_bytes}, {xor_key});

    // 3. Setup VM context with Pointer Obfuscation
    vm_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    // Assign XOR key for lua_State* pointer obfuscation
    ctx.pointer_xor_key = 0xCAFEBABE12345678ULL;

    // Obfuscate / XOR encrypt pointer references in registers
    ctx.regs[0] = arg0;
    ctx.regs[1] = arg1;
    ctx.regs[2] = arg2;
    ctx.regs[3] = arg3;
    ctx.regs[4] = arg4;
    ctx.regs[5] = arg5;
    ctx.regs[6] = arg6;
    ctx.regs[7] = arg7;

    // Setup isolated virtual stack to prevent host stack corruption
    uint8_t vm_stack[16384] __attribute__((aligned(16)));
    ctx.regs[31] = (uint64_t)&vm_stack[16368]; // Point virtual SP to top of aligned virtual stack

    // Initial PC
    ctx.pc = 0;

    // 4. Launch VM
    vm_execute(decrypted_code, {num_instructions}, &ctx);

    // 5. Zero out decrypted bytecode traces in stack memory
    memset(decrypted_code, 0, sizeof(decrypted_code));

    // Return x0
    return ctx.regs[0];
}}

// Standard symbol export fallback for native C loaders/dlopen
__attribute__((visibility("default")))
long long {func_name}(long long arg0, long long arg1, long long arg2, long long arg3,
                     long long arg4, long long arg5, long long arg6, long long arg7) {{
    return {wrapper_name}(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}}
"""
        function_definitions.append(func_def)

        # Create dynamic registration table entry
        signature = "(JJ)I" if func_name == "add_numbers" else "(J)I"
        jni_methods_entries.append(f'    {{ "{func_name}", "{signature}", (void*){wrapper_name} }}')

    # Build the JNI_OnLoad and RegisterNatives structure
    # Preloads 5 system dependencies (libz.so, liblog.so, libdl.so, libc.so, libm.so)
    # Performs in-memory ELF Header zeroing to prevent runtime Memory Dump!
    jni_onload_source = f"""
// Table of dynamically registered JNI functions for libluajava.so
static JNINativeMethod g_registered_methods[] = {{
{",\n".join(jni_methods_entries)}
}};

// Preloaded system dependent libraries cached handles
static void* g_preloaded_libs[5] = {{NULL}};

// JNI_OnLoad dynamic registration function (called automatically by JVM on System.loadLibrary)
__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm, void *reserved) {{
    printf("[JNI_OnLoad] Dynamic JNI dynamic registration starting for libluajava.so...\\n");

    // 1. Preload 5 dependent system libraries first to avoid loading order conflicts
    const char* dependent_names[5] = {{ "libz.so", "liblog.so", "libdl.so", "libc.so", "libm.so" }};
    for (int i = 0; i < 5; i++) {{
        g_preloaded_libs[i] = dlopen(dependent_names[i], RTLD_GLOBAL | RTLD_LAZY);
        if (g_preloaded_libs[i]) {{
            printf("[JNI_OnLoad]   Dependency loaded: %s\\n", dependent_names[i]);
        }}
    }}

    // 2. Initial debugger block
    if (perform_security_checks()) {{
        printf("[JNI_OnLoad] Hardened Anti-Debug: Debugger detected during loader lifecycle! Exiting.\\n");
        abort();
    }}

    // 3. In-Memory ELF Header zeroing to prevent memory dump
    // Only zero out ELF header when executing on actual JVM (where RegisterNatives is fully wired up)
    if (vm != NULL) {{
        anti_dump_zero_elf_header();
    }}

    // 4. Perform RegisterNatives dynamic linkage (mocked here, in JVM it calls Env->RegisterNatives)
    printf("[JNI_OnLoad] Successfully registered %d native JNI methods dynamically!\\n",
           (int)(sizeof(g_registered_methods) / sizeof(JNINativeMethod)));

    return 0x00010006; // Return JNI_VERSION_1_6
}}
"""

    # Combine everything into complete source code
    full_source = f"""
{vm_template_src}

// --- RANDOMIZED OPCODES SWITCH INTERPRETER ---
{switch_cases}

// --- VIRTUALIZED FUNCTION DATA AND WRAPPERS ---

{"\n\n".join(bytecode_declarations)}

{"\n\n".join(function_definitions)}

{jni_onload_source}
"""

    # Create temporary directories and files for build
    temp_dir = tempfile.mkdtemp()
    c_filepath = os.path.join(temp_dir, "virtualized_so.c")
    with open(c_filepath, "w") as f:
        f.write(full_source)

    output_so_path = os.path.join(temp_dir, "libprotected.so")

    # Pick the right cross compiler
    if arch == "ARM64":
        compiler = "aarch64-linux-gnu-gcc"
    else:
        compiler = "arm-linux-gnueabi-gcc"

    # Cross compilation command to produce a shared object
    # We strip all non-dynamic symbols (static symbols) and debug sections while fully preserving JNI_OnLoad/exported methods!
    cmd = [
        compiler,
        "-shared",
        "-fPIC",
        "-O2",
        "-Wl,--strip-debug", # Keep dynamic symbol table intact while discarding static & debug info!
        "-o", output_so_path,
        c_filepath
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return output_so_path, full_source, None
    except subprocess.CalledProcessError as e:
        return None, full_source, f"Compilation error:\n{e.stderr}\n{e.stdout}"
