-- Demonstration of using pure Lua 5.3 to parse an ARM64 .so file and simulate execution.
-- This parses tests/libtest_arm64.so, finds the function 'add_numbers', extracts its binary bytes,
-- decodes each 32-bit instruction word, and executes it on our pure Lua emulator!

local arm64 = require("arm64_emu")

print("=== Phase 1: Parsing tests/libtest_arm64.so in Pure Lua ===")
local exports, err = arm64.load_elf_so("tests/libtest_arm64.so")
if not exports then
    print("Error loading ELF SO: " .. tostring(err))
    os.exit(1)
end

print("Successfully parsed ELF dynamic symbol table! Found exported functions:")
for name, info in pairs(exports) do
    print(string.format("  - Symbol: %-15s | Virtual Addr: 0x%08X | Size: %3d bytes", name, info.vaddr, info.size))
end

local target_func = exports["add_numbers"]
if not target_func then
    print("Error: 'add_numbers' function not found in exports.")
    os.exit(1)
end

print(string.format("\n=== Phase 2: Decoding Machine Code of '%s' ===", target_func.name))
local bytes = target_func.bytes
local instructions = {}
local base_vaddr = target_func.vaddr

-- Extract 32-bit little-endian instruction words and decode them
for offset = 0, #bytes - 1, 4 do
    local b1, b2, b3, b4 = bytes:byte(offset + 1, offset + 4)
    if b1 and b2 and b3 and b4 then
        local word = b1 | (b2 << 8) | (b3 << 16) | (b4 << 24)
        local decoded = arm64.decode_binary_word(word)
        local addr = base_vaddr + offset
        instructions[addr] = decoded

        -- Formulate printable mnemonic
        local op_desc = decoded.op
        if decoded.op1 then op_desc = op_desc .. " x" .. decoded.op1 end
        if decoded.op2 then op_desc = op_desc .. ", x" .. decoded.op2 end
        if decoded.op3 then op_desc = op_desc .. ", " .. (decoded.is_imm and "#" or "x") .. decoded.op3 end

        print(string.format("  0x%08X: %08X -> decoded: %s", addr, word, op_desc))
    end
end

print("\n=== Phase 3: Launching Simulation ===")
local cpu = arm64.new_cpu()

-- Set up JNI/function arguments: x0 = 17, x1 = 28
cpu:set_reg(0, 17)
cpu:set_reg(1, 28)
cpu.pc = base_vaddr -- Set PC to function entry point

print(string.format("Initial CPU Register Inputs: x0 = %d, x1 = %d, SP = 0x%08X", cpu:get_reg(0), cpu:get_reg(1), cpu.sp))

local step_count = 0
while true do
    local current_pc = cpu.pc
    local insn = instructions[current_pc]
    if not insn then
        print(string.format("\n[CPU Halted] No instruction loaded at PC: 0x%08X", current_pc))
        break
    end

    step_count = step_count + 1

    -- Format instruction details
    local insn_desc = insn.op
    if insn.op1 then insn_desc = insn_desc .. " x" .. insn.op1 end
    if insn.op2 then insn_desc = insn_desc .. ", x" .. insn.op2 end
    if insn.op3 then insn_desc = insn_desc .. ", " .. (insn.is_imm and "#" or "x") .. insn.op3 end

    local success, step_err = arm64.step(cpu, insn)
    if not success then
        print(string.format("\n[CPU Segfault] Error at PC 0x%08X: %s", current_pc, tostring(step_err)))
        break
    end

    print(string.format("\nStep %d | Executed: 0x%08X: %s", step_count, current_pc, insn_desc))
    print(string.format("  PC: 0x%08X | x0: %d | x1: %d | x2: %d | LR (x30): 0x%08X", cpu.pc, cpu:get_reg(0), cpu:get_reg(1), cpu:get_reg(2), cpu:get_reg(30)))

    if insn.op == "RET" then
        print("\n[CPU Ret] Function returned successfully!")
        print(string.format("Final Return Value (x0): %d", cpu:get_reg(0)))
        break
    end

    if step_count > 50 then
        print("\n[CPU Timeout] Loop guard triggered.")
        break
    end
end
