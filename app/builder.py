import os
import subprocess
import tempfile
from app.vm_defs import VMOpcode

def generate_virtualized_so(arch: str, selected_funcs: list, original_so_path: str):
    """
    Generates a new C file combining:
    1. The core VM loader/interpreter
    2. The translated functions represented as VM bytecodes
    3. Re-exposes the selected exported functions under their original names.
    4. Anti-debug triggers that prompt abort() if TracerPid is active.

    Then cross-compiles it to a new SO library.
    """
    # Load the VM core source template
    template_path = os.path.join(os.path.dirname(__file__), "vm_template.c")
    with open(template_path, "r") as f:
        vm_template_src = f.read()

    # Generate custom VM code tables for selected functions
    bytecode_declarations = []
    function_definitions = []

    for idx, func in enumerate(selected_funcs):
        func_name = func['name']
        instructions = func['instructions'] # List of VM instructions

        # Build instruction array definition
        array_name = f"vm_code_{idx}"
        array_size = len(instructions)

        inst_lines = []
        for inst in instructions:
            op = inst['op']
            size = inst['size']
            op1 = inst['op1']
            op2 = inst['op2']
            op3 = inst['op3']
            comment = inst['comment'].replace("*/", "* /") # prevent nested comments
            inst_lines.append(f"    {{ {op}, {size}, {op1}, {op2}, {op3} }}, // {comment}")

        bytecode_declarations.append(f"// VM Bytecode for {func_name}\nstatic vm_insn_t {array_name}[{array_size}] = {{\n" + ",\n".join(inst_lines) + "\n};")

        # Build standard JNI function wrapper or standard exported symbol wrapper
        # The wrapper initializes the VM context, copies input registers (x0-x7 on ARM64) and executes VM
        func_def = f"""
// Exported virtualized function: {func_name}
__attribute__((visibility("default")))
long long {func_name}(long long arg0, long long arg1, long long arg2, long long arg3,
                     long long arg4, long long arg5, long long arg6, long long arg7) {{

    // 1. Runtime Anti-Debugger check
    if (detect_debugger()) {{
        printf("[VM Guardian] Debugger detected! Exiting execution.\\n");
        abort();
    }}

    // 2. Setup VM context
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

    // 3. Launch VM
    vm_execute({array_name}, {array_size}, &ctx);

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
