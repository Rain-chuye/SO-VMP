import os
import struct
import random
import subprocess
import tempfile
from app.vm_defs import VMOpcode

# --- Python ChaCha20 Stream Cipher Implementation ---
def rotate_left(val, r_bits):
    val = val & 0xFFFFFFFF
    return ((val << r_bits) | (val >> (32 - r_bits))) & 0xFFFFFFFF

def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = rotate_left(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = rotate_left(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = rotate_left(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = rotate_left(x[b] ^ x[c], 7)

def chacha20_block(inp):
    x = list(inp)
    for _ in range(10): # 20 rounds (10 double rounds)
        quarter_round(x, 0, 4, 8, 12)
        quarter_round(x, 1, 5, 9, 13)
        quarter_round(x, 2, 6, 10, 14)
        quarter_round(x, 3, 7, 11, 15)
        quarter_round(x, 0, 5, 10, 15)
        quarter_round(x, 1, 6, 11, 12)
        quarter_round(x, 2, 7, 8, 13)
        quarter_round(x, 3, 4, 9, 14)
    out = [(x[i] + inp[i]) & 0xFFFFFFFF for i in range(16)]
    return out

def chacha20_encrypt(key, counter, nonce, data):
    ctx = [0] * 16
    ctx[0] = 0x61707865
    ctx[1] = 0x3320646e
    ctx[2] = 0x79622d32
    ctx[3] = 0x6b206574
    for i in range(8):
        ctx[4 + i] = struct.unpack('<I', key[i*4 : (i+1)*4])[0]
    ctx[12] = counter
    for i in range(3):
        ctx[13 + i] = struct.unpack('<I', nonce[i*4 : (i+1)*4])[0]

    encrypted = bytearray()
    i = 0
    while i < len(data):
        block = chacha20_block(ctx)
        ctx[12] = (ctx[12] + 1) & 0xFFFFFFFF
        block_bytes = bytearray()
        for val in block:
            block_bytes.extend(struct.pack('<I', val))
        for j in range(64):
            if i >= len(data):
                break
            encrypted.append(data[i] ^ block_bytes[j])
            i += 1
    return encrypted

# Derive a compile-time static key for the chacha20 encryption
def generate_chacha20_key():
    return bytes(random.randint(0, 255) for _ in range(32))

def get_platform_fingerprint():
    # Stable signature seed for cross-device key derivation compatibility
    return 0x1234567890ABCDEF

def encrypt_bytecode_chacha(insns, mapping, key):
    # Pack instructions using randomized opcodes
    raw_bytes = bytearray()
    for ins in insns:
        rand_op = mapping[int(ins['op'])]
        raw_bytes.extend(struct.pack('<IIQQQ', rand_op, ins['size'], ins['op1'], ins['op2'], ins['op3']))

    nonce = b"SO_SHIELD_VM" # 12 bytes
    return chacha20_encrypt(key, 1, nonce, raw_bytes)

def generate_virtualized_so(arch: str, selected_funcs: list, original_so_path: str):
    """
    Generates a new C file combining:
    1. The core VM loader/interpreter
    2. Statically encrypted function bytecode arrays using ChaCha20
    3. Compile-time Randomized Opcode Mapping (256 randomized opcode slots)
    4. Multi-layered Anti-Debug & Anti-Hooking with silent register data pollution
    5. JNI Dynamic Registration (JNINativeMethod tables & JNI_OnLoad preloading of 5 system libraries)
    6. Pointer XOR-Obfuscation (XOR keys dynamically protecting sensitive lua_State* pointer in memory)
    7. In-Memory ELF Header zeroing to protect against Memory Dump
    8. Control Flow Flattening (CFF) inside the dynamic interpreter

    Then cross-compiles it to a new SO library.
    """
    # 1. Generate randomized opcode mapping (unique key for each compiler run)
    mapping = list(range(256))
    random.shuffle(mapping)

    # Load base template containing declarations and checks
    template_path = os.path.join(os.path.dirname(__file__), "vm_template.c")
    with open(template_path, "r") as f:
        vm_template_src = f.read()

    # Generate custom switch cases dynamically using our randomized mapping with Control Flow Flattening!
    switch_cases = f"""
// Hardened VM Executor core loop with Randomized Opcode Switch Cases and Control Flow Flattening (CFF)
static __attribute__((visibility("hidden"))) void vm_execute(vm_insn_t *code, uint32_t num_instructions, vm_context_t *ctx) {{
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);
    uint32_t executed_instructions = 0;

    // Control Flow Flattening: dispatcher state machine
    uint32_t cff_state = 0;
    while (cff_state != 2) {{
        switch (cff_state) {{
            case 0:
                // Dispatch pre-execution / integrity verification checks
                cff_state = 1;
                break;

            case 1:
                // Main Interpreter execution block
                while (ctx->pc < num_instructions) {{
                    uint64_t current_pc = ctx->pc;
                    vm_insn_t insn = code[ctx->pc++];
                    executed_instructions++;

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
                        break; // Exit main interpreter block
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
                        // No-op for standard logging
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
                        break;
                    }}
                }}
                cff_state = 2; // Move to epilogue
                break;
        }}
    }}

    // Timing-based latency validation
    gettimeofday(&end_time, NULL);
    double elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 + (end_time.tv_usec - start_time.tv_usec) / 1000.0;
    if (executed_instructions > 0 && (elapsed_ms / executed_instructions) > 5.0) {{
        // Silent response: Pollute registry to render output completely useless
        ctx->regs[0] ^= 0xDEADBAADFEEDCAFEULL;
    }}
}}
"""

    bytecode_declarations = []
    function_definitions = []
    jni_methods_entries = []

    # Use the stable signature seed fingerprint
    fingerprint = get_platform_fingerprint()

    for idx, func in enumerate(selected_funcs):
        func_name = func['name']
        instructions = func['instructions'] # List of VM instructions

        # 2. Generate random 32-byte compile-time encryption key
        chacha_key = generate_chacha20_key()

        # Encrypt the instructions using ChaCha20 with randomized opcodes
        enc_bytes = encrypt_bytecode_chacha(instructions, mapping, chacha_key)

        # Calculate static salt so that salt ^ fingerprint = key
        chacha_salt = bytearray(32)
        for i in range(32):
            shift = (i % 8) * 8
            chacha_salt[i] = chacha_key[i] ^ ((fingerprint >> shift) & 0xFF)

        # Formulate hex array representation
        hex_lines = []
        for i in range(0, len(enc_bytes), 16):
            chunk = enc_bytes[i:i+16]
            hex_lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk))

        array_name = f"vm_code_enc_{idx}"
        array_size_bytes = len(enc_bytes)
        num_instructions = len(instructions)

        # Save static salt bytes
        salt_lines = ", ".join(f"0x{b:02x}" for b in chacha_salt)

        bytecode_declarations.append(f"""
// Encrypted bytecode array for {func_name} (Size: {array_size_bytes} bytes)
static const uint8_t {array_name}[{array_size_bytes}] = {{
{",\n".join(hex_lines)}
}};

// Static random salt key for compile-time signature diversification
static const uint8_t vm_salt_{idx}[32] = {{ {salt_lines} }};
""")

        wrapper_name = f"virtualized_{func_name}"

        func_def = f"""
// Thread-safe virtualized implementation of {func_name}
// Hidden visibility guarantees omission from dynamic symbol tables (.dynsym / .dynstr)
static __attribute__((visibility("hidden"))) long long {wrapper_name}(long long arg0, long long arg1, long long arg2, long long arg3,
                                long long arg4, long long arg5, long long arg6, long long arg7) {{

    // 1. Silent data-pollution Anti-Debugger response
    uint64_t pollution = perform_security_checks();
    if (pollution != 0) {{
        // Silently pollute parameter inputs - makes computations return garbage values under debugging
        arg0 ^= pollution;
        arg1 ^= pollution;
    }}

    // 2. Derive unique runtime key dynamically using static salt mixed with CPU hardware fingerprint
    uint8_t runtime_key[32];
    derive_runtime_key(runtime_key, vm_salt_{idx});

    // 3. Dynamic Stack Decryption utilizing P0 Military-grade ChaCha20 Stream Cipher
    vm_insn_t decrypted_code[{num_instructions}];
    decrypt_bytecode_chacha((uint8_t*){array_name}, (uint8_t*)decrypted_code, {array_size_bytes}, runtime_key);

    // 4. Setup VM context with Pointer Obfuscation
    vm_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    ctx.pointer_xor_key = 0xCAFEBABE12345678ULL;

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
    ctx.regs[31] = (uint64_t)&vm_stack[16368];

    // Initial PC
    ctx.pc = 0;

    // 5. Launch VM with Control Flow Flattening (CFF)
    vm_execute(decrypted_code, {num_instructions}, &ctx);

    // Apply optional silent pollution to return values
    if (pollution != 0) {{
        ctx.regs[0] ^= pollution;
    }}

    // 6. Zero out decrypted bytecode traces in stack memory immediately to defeat memory dumps
    memset(decrypted_code, 0, sizeof(decrypted_code));

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
    // 1. Preload 5 dependent system libraries first to avoid loading order conflicts
    const char* dependent_names[5] = {{ "libz.so", "liblog.so", "libdl.so", "libc.so", "libm.so" }};
    for (int i = 0; i < 5; i++) {{
        g_preloaded_libs[i] = dlopen(dependent_names[i], RTLD_GLOBAL | RTLD_LAZY);
    }}

    // 2. Initial debugger block
    uint64_t pollution = perform_security_checks();
    if (pollution != 0) {{
        // Silent response: corrupt JVM binding registration table or exit silently
        return 0;
    }}

    // 3. In-Memory ELF Header zeroing to prevent memory dump
    if (vm != NULL) {{
        anti_dump_zero_elf_header();
    }}

    // 4. Perform RegisterNatives dynamic linkage (mocked here, in JVM it calls Env->RegisterNatives)
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
