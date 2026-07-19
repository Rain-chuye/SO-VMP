import re
from app.vm_defs import VMOpcode

def translate_arm64_to_vm(instructions):
    """
    Translates disassembled ARM64 instructions to custom VM Instructions.
    Each VM instruction has:
    - op: VMOpcode
    - operands: 3 integers (could represent register indices or immediate values)
    - comment: Original instruction string for reference
    """
    vm_instructions = []

    # Simple ARM64 register parsing (e.g. x0 -> 0, w0 -> 0, x30 -> 30, lr -> 30, sp -> 31)
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

    for insn in instructions:
        mnemonic = insn['mnemonic'].lower()
        op_str = insn['op_str'].lower()
        orig = f"{insn['mnemonic']} {insn['op_str']}"

        # Split operands by comma
        ops = [o.strip() for o in op_str.split(',') if o.strip()]

        vm_op = VMOpcode.VM_NOP
        op1, op2, op3 = 0, 0, 0

        if mnemonic == 'add':
            vm_op = VMOpcode.VM_ADD
            if len(ops) >= 3:
                op1 = parse_reg(ops[0])
                op2 = parse_reg(ops[1])
                if ops[2].startswith('#'):
                    # ADD Xd, Xn, #imm
                    # We can use a trick: store a flag or represent immediate in op3
                    op3 = parse_imm(ops[2])
                    # Let's say if op3 is immediate, we have a custom handling or separate opcode.
                    # For simplicity, we flag high bit of op3 to indicate IMM
                    op3 = op3 | 0x80000000
                else:
                    op3 = parse_reg(ops[2])
            elif len(ops) == 2:
                # ADD Xd, #imm or ADD Xd, Xn
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
            # Often ORR Xd, XZR, Xn is a MOV
            # Or ORR Xd, XZR, #imm
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
            # Parse [x0, #8] or [x0]
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

        elif mnemonic == 'b':
            vm_op = VMOpcode.VM_B
            # Target offset or label
            op1 = parse_imm(ops[0]) if ops[0].startswith('#') else 0

        elif mnemonic in ('b.eq', 'beq'):
            vm_op = VMOpcode.VM_B_EQ
            op1 = parse_imm(ops[0]) if ops[0].startswith('#') else 0

        elif mnemonic in ('b.ne', 'bne'):
            vm_op = VMOpcode.VM_B_NE
            op1 = parse_imm(ops[0]) if ops[0].startswith('#') else 0

        elif mnemonic in ('b.gt', 'bgt'):
            vm_op = VMOpcode.VM_B_GT
            op1 = parse_imm(ops[0]) if ops[0].startswith('#') else 0

        elif mnemonic in ('b.lt', 'blt'):
            vm_op = VMOpcode.VM_B_LT
            op1 = parse_imm(ops[0]) if ops[0].startswith('#') else 0

        elif mnemonic == 'cbz' and len(ops) == 2:
            vm_op = VMOpcode.VM_CBZ
            op1 = parse_reg(ops[0])
            op2 = parse_imm(ops[1]) if ops[1].startswith('#') else 0

        elif mnemonic == 'cbnz' and len(ops) == 2:
            vm_op = VMOpcode.VM_CBNZ
            op1 = parse_reg(ops[0])
            op2 = parse_imm(ops[1]) if ops[1].startswith('#') else 0

        elif mnemonic == 'bl':
            vm_op = VMOpcode.VM_BL
            # Call target
            op1 = parse_imm(ops[0]) if ops[0].startswith('#') else 0

        elif mnemonic == 'ret':
            vm_op = VMOpcode.VM_RET
            if len(ops) > 0:
                op1 = parse_reg(ops[0])
            else:
                op1 = 30 # Default lr (x30)

        else:
            # Fallback NOP or generic VM instructions
            vm_op = VMOpcode.VM_NOP

        vm_instructions.append({
            "address": insn['address'],
            "op": int(vm_op),
            "op_name": vm_op.name,
            "op1": op1,
            "op2": op2,
            "op3": op3,
            "comment": orig
        })

    return vm_instructions
