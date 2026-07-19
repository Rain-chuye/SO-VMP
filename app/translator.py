import re
from app.vm_defs import VMOpcode

def translate_arm64_to_vm(instructions):
    """
    Translates disassembled ARM64 instructions to custom VM Instructions.
    Each VM instruction has:
    - op: VMOpcode
    - size: Operand size in bytes (4 for w-registers, 8 for x-registers)
    - operands: 3 integers (could represent register indices or immediate values)
    - comment: Original instruction string for reference
    """
    # Pass 1: Build mapping from physical address to instruction index
    addr_to_index = {}
    for idx, insn in enumerate(instructions):
        addr_to_index[insn['address']] = idx

    def parse_reg(reg_str):
        reg_str = reg_str.strip().lower()
        if reg_str == 'sp':
            return 31
        if reg_str in ('lr', 'x30'):
            return 30
        if reg_str in ('fp', 'x29'):
            return 29
        # Match x0-x30, w0-w30
        match = re.match(r'^[xw](\d+)$', reg_str)
        if match:
            return int(match.group(1))
        return 0 # Default fallback

    def parse_imm(imm_str):
        imm_str = imm_str.strip().lower()
        if imm_str.startswith('#'):
            imm_str = imm_str[1:]
        # Hex or decimal
        try:
            if imm_str.startswith('0x'):
                return int(imm_str, 16)
            return int(imm_str)
        except ValueError:
            return 0

    def extract_branch_target(op_str):
        # Extracts hex (0x5b8) or decimal (1472) target from op_str
        match = re.search(r'0x[0-9a-fA-F]+', op_str)
        if match:
            return int(match.group(0), 16)
        match = re.search(r'\b\d+\b', op_str)
        if match:
            return int(match.group(0))
        return None

    vm_instructions = []

    for idx, insn in enumerate(instructions):
        mnemonic = insn['mnemonic'].lower()
        op_str = insn['op_str'].lower()
        orig = f"{insn['mnemonic']} {insn['op_str']}"

        # Split operands ignoring commas inside square brackets
        ops = []
        current = ""
        in_bracket = False
        for char in op_str:
            if char == '[':
                in_bracket = True
            elif char == ']':
                in_bracket = False

            if char == ',' and not in_bracket:
                ops.append(current.strip())
                current = ""
            else:
                current += char
        if current.strip():
            ops.append(current.strip())

        vm_op = VMOpcode.VM_NOP
        size = 8 # Default 64-bit size
        op1, op2, op3 = 0, 0, 0

        # Check size based on destination/first register name (w-reg vs x-reg)
        if len(ops) > 0:
            reg_name = ops[0].strip().lower()
            if reg_name.startswith('w'):
                size = 4

        if mnemonic == 'add':
            vm_op = VMOpcode.VM_ADD
            if len(ops) >= 3:
                op1 = parse_reg(ops[0])
                op2 = parse_reg(ops[1])
                if ops[2].startswith('#'):
                    op3 = parse_imm(ops[2])
                    op3 = op3 | 0x80000000
                else:
                    op3 = parse_reg(ops[2])
            elif len(ops) == 2:
                op1 = parse_reg(ops[0])
                if ops[1].startswith('#'):
                    op2 = op1
                    op3 = parse_imm(ops[1]) | 0x80000000
                else:
                    op2 = op1
                    op3 = parse_reg(ops[1])

        elif mnemonic == 'sub':
            vm_op = VMOpcode.VM_SUB
            if len(ops) >= 3:
                op1 = parse_reg(ops[0])
                op2 = parse_reg(ops[1])
                if ops[2].startswith('#'):
                    op3 = parse_imm(ops[2]) | 0x80000000
                else:
                    op3 = parse_reg(ops[2])
            elif len(ops) == 2:
                op1 = parse_reg(ops[0])
                if ops[1].startswith('#'):
                    op2 = op1
                    op3 = parse_imm(ops[1]) | 0x80000000
                else:
                    op2 = op1
                    op3 = parse_reg(ops[1])

        elif mnemonic in ('mov', 'orr') and len(ops) == 2:
            vm_op = VMOpcode.VM_MOV
            op1 = parse_reg(ops[0])
            if ops[1].startswith('#'):
                op2 = parse_imm(ops[1])
                op3 = 1 # Flag indicating immediate
            else:
                op2 = parse_reg(ops[1])
                op3 = 0 # Register

        elif mnemonic == 'cmp' and len(ops) == 2:
            vm_op = VMOpcode.VM_CMP
            op1 = parse_reg(ops[0])
            if ops[1].startswith('#'):
                op2 = parse_imm(ops[1])
                op3 = 1 # Flag immediate
            else:
                op2 = parse_reg(ops[1])
                op3 = 0

        elif mnemonic == 'ldr' and len(ops) >= 2:
            vm_op = VMOpcode.VM_LDR
            op1 = parse_reg(ops[0])
            mem_str = ops[1].strip()
            if mem_str.startswith('[') and mem_str.endswith(']'):
                inner = mem_str[1:-1].split(',')
                op2 = parse_reg(inner[0])
                if len(inner) > 1:
                    op3 = parse_imm(inner[1])
                else:
                    op3 = 0

        elif mnemonic == 'str' and len(ops) >= 2:
            vm_op = VMOpcode.VM_STR
            op1 = parse_reg(ops[0])
            mem_str = ops[1].strip()
            if mem_str.startswith('[') and mem_str.endswith(']'):
                inner = mem_str[1:-1].split(',')
                op2 = parse_reg(inner[0])
                if len(inner) > 1:
                    op3 = parse_imm(inner[1])
                else:
                    op3 = 0

        elif mnemonic in ('lsl', 'lsr'):
            vm_op = VMOpcode.VM_LSL if mnemonic == 'lsl' else VMOpcode.VM_LSR
            if len(ops) >= 3:
                op1 = parse_reg(ops[0])
                op2 = parse_reg(ops[1])
                if ops[2].startswith('#'):
                    op3 = parse_imm(ops[2]) | 0x80000000
                else:
                    op3 = parse_reg(ops[2])
            elif len(ops) == 2:
                op1 = parse_reg(ops[0])
                if ops[1].startswith('#'):
                    op2 = op1
                    op3 = parse_imm(ops[1]) | 0x80000000
                else:
                    op2 = op1
                    op3 = parse_reg(ops[1])

        elif mnemonic == 'b':
            vm_op = VMOpcode.VM_B
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic in ('b.eq', 'beq'):
            vm_op = VMOpcode.VM_B_EQ
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic in ('b.ne', 'bne'):
            vm_op = VMOpcode.VM_B_NE
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic in ('b.gt', 'bgt'):
            vm_op = VMOpcode.VM_B_GT
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic in ('b.lt', 'blt'):
            vm_op = VMOpcode.VM_B_LT
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic in ('b.le', 'ble'):
            vm_op = VMOpcode.VM_B_LE
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic in ('b.ge', 'bge'):
            vm_op = VMOpcode.VM_B_GE
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic == 'cbz' and len(ops) == 2:
            vm_op = VMOpcode.VM_CBZ
            op1 = parse_reg(ops[0])
            target = extract_branch_target(ops[1])
            op2 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic == 'cbnz' and len(ops) == 2:
            vm_op = VMOpcode.VM_CBNZ
            op1 = parse_reg(ops[0])
            target = extract_branch_target(ops[1])
            op2 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic == 'bl':
            vm_op = VMOpcode.VM_BL
            target = extract_branch_target(ops[0])
            op1 = addr_to_index.get(target, 0) if target in addr_to_index else 0

        elif mnemonic == 'ret':
            vm_op = VMOpcode.VM_RET
            if len(ops) > 0:
                op1 = parse_reg(ops[0])
            else:
                op1 = 30 # Default lr (x30)

        else:
            vm_op = VMOpcode.VM_NOP

        vm_instructions.append({
            "address": insn['address'],
            "op": int(vm_op),
            "op_name": vm_op.name,
            "size": size,
            "op1": op1,
            "op2": op2,
            "op3": op3,
            "comment": orig
        })

    return vm_instructions
