import sys
import os

# Adjust path to import app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.elf_analyzer import analyze_so, disassemble_func
from app.translator import translate_arm64_to_vm
from app.builder import generate_virtualized_so

def test_full_flow():
    so_path = "tests/libtest_arm64.so"
    print(f"Analyzing {so_path}...")
    analysis = analyze_so(so_path)
    arch = analysis["arch"]
    print(f"Arch: {arch}")

    # We want to virtualize "add_numbers" and "check_logic"
    selected_funcs = ["add_numbers", "check_logic"]
    selected_funcs_data = []

    for f_name in selected_funcs:
        func_entry = next((x for x in analysis["exports"] if x["name"] == f_name), None)
        if not func_entry:
            print(f"Error: function {f_name} not found in exports!")
            return False

        print(f"Disassembling {f_name} at 0x{func_entry['address']:x} (size: {func_entry['size']})...")
        raw_instructions = disassemble_func(so_path, arch, func_entry["address"], func_entry["size"])
        print(f"Disassembled {len(raw_instructions)} instructions.")

        vm_instructions = translate_arm64_to_vm(raw_instructions)
        print(f"Translated to {len(vm_instructions)} VM instructions.")
        selected_funcs_data.append({
            "name": f_name,
            "instructions": vm_instructions
        })

    print("Building virtualized SO...")
    output_so, c_source, err = generate_virtualized_so(arch, selected_funcs_data, so_path)
    if err:
        print(f"Build failed: {err}")
        print("Source Code produced:")
        print(c_source)
        return False

    print(f"Build succeeded! Output SO placed at: {output_so}")

    # Copy compiled SO to current directory as 'libprotected.so'
    import shutil
    dest = "libprotected.so"
    shutil.copy2(output_so, dest)
    print(f"Copied to {dest}")
    return True

if __name__ == "__main__":
    success = test_full_flow()
    sys.exit(0 if success else 1)
