-- ARM64 (AArch64) Instruction Emulator and ELF Loader in pure Lua 5.3
-- Supports key registers, memory state, and instruction parsing for:
-- ADD, SUB, LDR, STR, CMP, B, B.cond (B.EQ, B.NE, B.LT, B.GT, B.LE, B.GE), CBZ, CBNZ, BL, RET

local arm64 = {}

-- Create a new CPU state/context
function arm64.new_cpu()
    local cpu = {
        regs = {},       -- x0 to x30 registers (64-bit values)
        sp = 0x7FFF0000, -- stack pointer
        pc = 0,          -- program counter
        memory = {},     -- Simulated memory hash table key=address, value=uint8
        cpsr = {         -- Condition Flags
            Z = false,   -- Zero Flag
            N = false,   -- Negative Flag
            C = false,   -- Carry Flag
            V = false,   -- Overflow Flag
        }
    }

    -- Initialize x0-x30 registers to 0
    for i = 0, 30 do
        cpu.regs[i] = 0
    end

    -- Helper functions for memory access (little endian)
    function cpu:read_u8(addr)
        return self.memory[addr] or 0
    end

    function cpu:write_u8(addr, val)
        self.memory[addr] = val & 0xFF
    end

    function cpu:read_u64(addr)
        local val = 0
        for i = 0, 7 do
            val = val + (self:read_u8(addr + i) * (256 ^ i))
        end
        return val
    end

    function cpu:write_u64(addr, val)
        for i = 0, 7 do
            local byte = (val >> (i * 8)) & 0xFF
            self:write_u8(addr + i, byte)
        end
    end

    function cpu:get_reg(reg_id)
        if reg_id == 31 or reg_id == "sp" then
            return self.sp
        end
        return self.regs[reg_id] or 0
    end

    function cpu:set_reg(reg_id, val)
        if reg_id == 31 or reg_id == "sp" then
            self.sp = val
        else
            self.regs[reg_id] = val
        end
    end

    return cpu
end

-- ELF64 Shared Library (.so) Parser in Pure Lua
function arm64.load_elf_so(filepath)
    local f = io.open(filepath, "rb")
    if not f then
        return nil, "Failed to open file: " .. tostring(filepath)
    end

    local content = f:read("*a")
    f:close()

    -- Verify magic bytes
    if #content < 64 then
        return nil, "File too small for ELF64"
    end

    local magic = content:sub(1, 4)
    if magic ~= "\x7fELF" then
        return nil, "Invalid ELF magic"
    end

    local class = string.unpack("<I1", content, 5)
    if class ~= 2 then
        return nil, "Not a 64-bit ELF file"
    end

    local machine = string.unpack("<I2", content, 19)
    if machine ~= 183 then -- 0xB7 for AArch64
        return nil, "Not an AArch64 (ARM64) ELF file (machine=" .. tostring(machine) .. ")"
    end

    local e_phoff = string.unpack("<I8", content, 33)
    local e_shoff = string.unpack("<I8", content, 41)
    local e_phnum = string.unpack("<I2", content, 57)
    local e_shentsize = string.unpack("<I2", content, 59)
    local e_shnum = string.unpack("<I2", content, 61)
    local e_shstrndx = string.unpack("<I2", content, 63)

    -- 1. Parse PT_LOAD segments to resolve virtual addresses to file offsets
    local segments = {}
    for i = 0, e_phnum - 1 do
        local ph_offset = e_phoff + i * 56 + 1
        local p_type = string.unpack("<I4", content, ph_offset)
        if p_type == 1 then -- PT_LOAD
            local p_offset = string.unpack("<I8", content, ph_offset + 8)
            local p_vaddr = string.unpack("<I8", content, ph_offset + 16)
            local p_filesz = string.unpack("<I8", content, ph_offset + 32)
            local p_memsz = string.unpack("<I8", content, ph_offset + 40)
            table.insert(segments, {
                offset = p_offset,
                vaddr = p_vaddr,
                filesz = p_filesz,
                memsz = p_memsz
            })
        end
    end

    local function vaddr_to_offset(vaddr)
        for _, seg in ipairs(segments) do
            if vaddr >= seg.vaddr and vaddr < seg.vaddr + seg.memsz then
                return seg.offset + (vaddr - seg.vaddr)
            end
        end
        return vaddr -- Fallback
    end

    -- 2. Find .dynsym and .dynstr sections
    -- Read .shstrtab section header to resolve section names
    local shstr_offset = e_shoff + e_shstrndx * e_shentsize + 1
    local shstr_sec_offset = string.unpack("<I8", content, shstr_offset + 24)
    local shstr_sec_size = string.unpack("<I8", content, shstr_offset + 32)
    local shstrtab = content:sub(shstr_sec_offset + 1, shstr_sec_offset + shstr_sec_size)

    local function get_string(tab, offset)
        local end_idx = tab:find("\0", offset + 1)
        if not end_idx then return tab:sub(offset + 1) end
        return tab:sub(offset + 1, end_idx - 1)
    end

    local dynsym_offset, dynsym_size, dynsym_entsize
    local dynstr_sec_offset, dynstr_sec_size

    for i = 0, e_shnum - 1 do
        local sec_offset = e_shoff + i * e_shentsize + 1
        local sh_name_idx = string.unpack("<I4", content, sec_offset)
        local name = get_string(shstrtab, sh_name_idx)

        local sh_type = string.unpack("<I4", content, sec_offset + 4)
        if sh_type == 11 then -- SHT_DYNSYM
            dynsym_offset = string.unpack("<I8", content, sec_offset + 24)
            dynsym_size = string.unpack("<I8", content, sec_offset + 32)
            dynsym_entsize = string.unpack("<I8", content, sec_offset + 56) or 24
        elseif sh_type == 3 and name == ".dynstr" then -- SHT_STRTAB
            dynstr_sec_offset = string.unpack("<I8", content, sec_offset + 24)
            dynstr_sec_size = string.unpack("<I8", content, sec_offset + 32)
        end
    end

    if not dynsym_offset or not dynstr_sec_offset then
        return nil, "Could not find .dynsym or .dynstr sections"
    end

    local dynstr = content:sub(dynstr_sec_offset + 1, dynstr_sec_offset + dynstr_sec_size)

    -- 3. Extract Exported functions
    local exports = {}
    local num_syms = dynsym_size / dynsym_entsize
    for i = 0, num_syms - 1 do
        local sym_offset = dynsym_offset + i * dynsym_entsize + 1
        local st_name_idx = string.unpack("<I4", content, sym_offset)
        local name = get_string(dynstr, st_name_idx)

        local st_info = string.unpack("<I1", content, sym_offset + 4)
        local st_type = st_info & 0xF
        local st_value = string.unpack("<I8", content, sym_offset + 8)
        local st_size = string.unpack("<I8", content, sym_offset + 16)

        -- We want function symbols with valid addresses and sizes
        if name ~= "" and (st_type == 2 or st_type == 0) and st_value > 0 and st_size > 0 then
            local file_offset = vaddr_to_offset(st_value)
            local raw_bytes = content:sub(file_offset + 1, file_offset + st_size)
            exports[name] = {
                name = name,
                vaddr = st_value,
                size = st_size,
                file_offset = file_offset,
                bytes = raw_bytes
            }
        end
    end

    return exports, nil
end

-- Decodes a 32-bit ARM64 machine instruction word
function arm64.decode_binary_word(word)
    local sf = (word >> 31) & 1
    local op = (word >> 30) & 1
    local S  = (word >> 29) & 1
    local op_type = (word >> 22) & 0x7F

    -- 1. ADD / SUB (Immediate) - op_type 0x44 (e.g. SUB/ADD immediate)
    if op_type == 0x44 then
        local imm12 = (word >> 10) & 0xFFF
        local rn = (word >> 5) & 0x1F
        local rd = word & 0x1F

        -- If S == 1 and rd == 31, it's a CMP (immediate) alias
        if S == 1 and rd == 31 then
            return { op = "CMP", op1 = rn, op2 = imm12, is_imm = true }
        end

        local mnemonic = (op == 0) and "ADD" or "SUB"
        return { op = mnemonic, op1 = rd, op2 = rn, op3 = imm12, is_imm = true }
    end

    -- 2. ADD / SUB (Register) - op_type 0x2C
    if op_type == 0x2C then
        local rm = (word >> 16) & 0x1F
        local rn = (word >> 5) & 0x1F
        local rd = word & 0x1F

        -- If S == 1 and rd == 31, it's a CMP (register) alias
        if S == 1 and rd == 31 then
            return { op = "CMP", op1 = rn, op2 = rm, is_imm = false }
        end

        local mnemonic = (op == 0) and "ADD" or "SUB"
        return { op = mnemonic, op1 = rd, op2 = rn, op3 = rm, is_imm = false }
    end

    -- 3. B (Unconditional branch) - (word >> 26) & 0x3F == 0x05
    local b_op = (word >> 26) & 0x3F
    if b_op == 0x05 then
        local imm26 = word & 0x3FFFFFF
        -- Sign extend imm26 to 64-bit relative offset
        if (imm26 & 0x2000000) ~= 0 then
            imm26 = imm26 - 0x4000000
        end
        return { op = "B", op1 = imm26 * 4 }
    end

    -- 4. B.cond - op_type 0x50 (e.g. 0x54000040)
    if op_type == 0x50 then
        local imm19 = (word >> 5) & 0x7FFFF
        if (imm19 & 0x40000) ~= 0 then
            imm19 = imm19 - 0x80000
        end
        local cond = word & 0xF
        local cond_name = "EQ"
        if cond == 0 then cond_name = "EQ"
        elseif cond == 1 then cond_name = "NE"
        elseif cond == 2 then cond_name = "CS"
        elseif cond == 3 then cond_name = "CC"
        elseif cond == 10 then cond_name = "GE"
        elseif cond == 11 then cond_name = "LT"
        elseif cond == 12 then cond_name = "GT"
        elseif cond == 13 then cond_name = "LE"
        end
        return { op = "B." .. cond_name, op1 = imm19 * 4 }
    end

    -- 5. CBZ / CBNZ
    local cb_op = (word >> 24) & 0x7F
    if cb_op == 0x34 or cb_op == 0x35 then
        local mnemonic = (cb_op == 0x34) and "CBZ" or "CBNZ"
        local imm19 = (word >> 5) & 0x7FFFF
        if (imm19 & 0x40000) ~= 0 then
            imm19 = imm19 - 0x80000
        end
        local rt = word & 0x1F
        return { op = mnemonic, op1 = rt, op2 = imm19 * 4 }
    end

    -- 6. LDR / STR (Immediate, unsigned offset) - op_type 0x64 (STR), 0x65 (LDR)
    if op_type == 0x64 or op_type == 0x65 then
        local imm12 = (word >> 10) & 0xFFF
        local rn = (word >> 5) & 0x1F
        local rt = word & 0x1F

        -- For a 64-bit load/store, offset is imm12 scaled by 8
        local offset = imm12 * 8
        local mnemonic = (op_type == 0x65) and "LDR" or "STR"
        return { op = mnemonic, op1 = rt, op2 = rn, op3 = offset }
    end

    -- 7. RET - op_type 0x59
    if op_type == 0x59 and word == 0xD65F03C0 then
        return { op = "RET", op1 = 30 }
    end

    -- 8. BL (Branch with Link)
    local bl_op = (word >> 26) & 0x3F
    if bl_op == 0x25 then
        local imm26 = word & 0x3FFFFFF
        if (imm26 & 0x2000000) ~= 0 then
            imm26 = imm26 - 0x4000000
        end
        return { op = "BL", op1 = imm26 * 4 }
    end

    -- Fallback/Unimplemented
    return { op = "UNKNOWN", raw = word }
end

-- Executes one decoded instruction
function arm64.step(cpu, insn)
    if not insn or insn.op == "UNKNOWN" then
        return false, "Invalid or unknown instruction"
    end

    local op = insn.op
    local op1 = insn.op1
    local op2 = insn.op2
    local op3 = insn.op3

    if op == "ADD" then
        local val2 = cpu:get_reg(op2)
        local val3 = insn.is_imm and op3 or cpu:get_reg(op3)
        cpu:set_reg(op1, val2 + val3)
        cpu.pc = cpu.pc + 4

    elseif op == "SUB" then
        local val2 = cpu:get_reg(op2)
        local val3 = insn.is_imm and op3 or cpu:get_reg(op3)
        cpu:set_reg(op1, val2 - val3)
        cpu.pc = cpu.pc + 4

    elseif op == "CMP" then
        local val1 = cpu:get_reg(op1)
        local val2 = insn.is_imm and op2 or cpu:get_reg(op2)
        local diff = val1 - val2
        cpu.cpsr.Z = (diff == 0)
        cpu.cpsr.N = (diff < 0)
        cpu.pc = cpu.pc + 4

    elseif op == "LDR" then
        local base_addr = cpu:get_reg(op2)
        local addr = base_addr + op3
        local val = cpu:read_u64(addr)
        cpu:set_reg(op1, val)
        cpu.pc = cpu.pc + 4

    elseif op == "STR" then
        local val = cpu:get_reg(op1)
        local base_addr = cpu:get_reg(op2)
        local addr = base_addr + op3
        cpu:write_u64(addr, val)
        cpu.pc = cpu.pc + 4

    elseif op == "B" then
        cpu.pc = cpu.pc + op1

    elseif op == "B.EQ" then
        if cpu.cpsr.Z then
            cpu.pc = cpu.pc + op1
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "B.NE" then
        if not cpu.cpsr.Z then
            cpu.pc = cpu.pc + op1
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "B.LT" then
        if cpu.cpsr.N then
            cpu.pc = cpu.pc + op1
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "B.GT" then
        if not cpu.cpsr.Z and not cpu.cpsr.N then
            cpu.pc = cpu.pc + op1
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "B.LE" then
        if cpu.cpsr.Z or cpu.cpsr.N then
            cpu.pc = cpu.pc + op1
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "B.GE" then
        if not cpu.cpsr.N then
            cpu.pc = cpu.pc + op1
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "CBZ" then
        local val = cpu:get_reg(op1)
        if val == 0 then
            cpu.pc = cpu.pc + op2
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "CBNZ" then
        local val = cpu:get_reg(op1)
        if val ~= 0 then
            cpu.pc = cpu.pc + op2
        else
            cpu.pc = cpu.pc + 4
        end

    elseif op == "BL" then
        cpu:set_reg(30, cpu.pc + 4) -- Save return address in x30 (LR)
        cpu.pc = cpu.pc + op1

    elseif op == "RET" then
        cpu.pc = cpu:get_reg(op1) -- Return to address in register

    else
        return false, "Unsupported operation: " .. tostring(op)
    end

    return true, nil
end

return arm64
