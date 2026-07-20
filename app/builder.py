import os
import struct
import random
import subprocess
import tempfile
from app.vm_defs import VMOpcode

def encrypt_bytecode_rolling(insns, key):
    # Pack instructions into a continuous little-endian byte array
    # vm_insn_t: 32 bytes total (uint32_t op, uint32_t size, uint64_t op1, uint64_t op2, uint64_t op3)
    raw_bytes = bytearray()
    for ins in insns:
        raw_bytes.extend(struct.pack('<IIQQQ', ins['op'], ins['size'], ins['op1'], ins['op2'], ins['op3']))

    encrypted = bytearray()
    current_key = key
    for i, b in enumerate(raw_bytes):
        enc_b = b ^ current_key
        encrypted.append(enc_b)
        current_key = (current_key + b + i) & 0xFF

    return encrypted

def generate_virtualized_so(arch: str, selected_funcs: list, original_so_path: str):
    """
    Generates a new C file combining:
    1. The core VM loader/interpreter
    2. The encrypted function bytecode represented as static uint8_t arrays
    3. Re-exposes the selected exported functions under their original names.
    4. Anti-debug triggers that prompt abort() if TracerPid is active.

    Then cross-compiles it to a new SO library.
    """
    template_path = os.path.join(os.path.dirname(__file__), "vm_template.c")
    with open(template_path, "r") as f:
        vm_template_src = f.read()

    bytecode_declarations = []
    function_definitions = []

    for idx, func in enumerate(selected_funcs):
        func_name = func['name']
        instructions = func['instructions'] # List of VM instructions

        # Generate random rolling XOR key
        xor_key = random.randint(1, 254)

        # Encrypt the instructions
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

        # Build JNI/symbol wrapper that dynamically decrypts and zeroes bytecode on stack
        func_def = f"""
// Exported virtualized function with dynamic decryption: {func_name}
__attribute__((visibility("default")))
long long {func_name}(long long arg0, long long arg1, long long arg2, long long arg3,
                     long long arg4, long long arg5, long long arg6, long long arg7) {{

    // 1. Runtime Anti-Debugger check
    if (perform_security_checks()) {{
        printf("[VM Guardian] Security violation detected! Exiting execution.\\n");
        abort();
    }}

    // 2. Dynamic Stack Decryption
    vm_insn_t decrypted_code[{num_instructions}];
    decrypt_bytecode((uint8_t*){array_name}, (uint8_t*)decrypted_code, {array_size_bytes}, {xor_key});

    // 3. Setup VM context
    vm_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    // Pass args to registers x0 - x7
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
"""
        function_definitions.append(func_def)

    # Combine everything into complete source code
    full_source = f"""
{vm_template_src}

// --- VIRTUALIZED FUNCTION DATA AND WRAPPERS ---

{"\n\n".join(bytecode_declarations)}

{"\n\n".join(function_definitions)}
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
    cmd = [
        compiler,
        "-shared",
        "-fPIC",
        "-O2",
        "-o", output_so_path,
        c_filepath
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return output_so_path, full_source, None
    except subprocess.CalledProcessError as e:
        return None, full_source, f"Compilation error:\n{e.stderr}\n{e.stdout}"
