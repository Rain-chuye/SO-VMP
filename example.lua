-- Demonstration / Example file for testing the Pure Lua ARM64 CPU Emulator.
-- This file configures a state, preloads instructions into mock memory,
-- loads initial register inputs, and steps through the simulation, printing register and memory transitions.

local arm64 = require("arm64_emu")

local function print_cpu_state(cpu, step_num, insn_desc)
    print(string.format("\n================ [STEP %d: %s] ================", step_num, insn_desc))
    print(string.format("PC  : 0x%08X", cpu.pc))
    print(string.format("CPSR: Z=%s, N=%s", tostring(cpu.cpsr.Z), tostring(cpu.cpsr.N)))
    print("Registers:")
    for i = 0, 7 do
        print(string.format("  x%d: %016X    x%d: %016X", i, cpu:get_reg(i), i+8, cpu:get_reg(i+8)))
    end
    print(string.format("  x30 (LR): %016X   SP: %016X", cpu:get_reg(30), cpu:get_reg(31)))
    print("Memory Changes (Stack / Heap):")
    -- Print non-zero stack entries around SP
    local found_mem = false
    for offset = -16, 16, 8 do
        local addr = cpu.sp + offset
        local val = cpu:read_u64(addr)
        if val ~= 0 then
            print(string.format("  [SP%+03d] 0x%08X -> %016X", offset, addr, val))
            found_mem = true
        end
    end
    if not found_mem then
        print("  (No stack memory allocated/modified)")
    end
end

-- Initialize the Virtual CPU
local cpu = arm64.new_cpu()

-- Set up some initial inputs in registers x0 and x1
cpu:set_reg(0, 100) -- x0 = 100
cpu:set_reg(1, 250) -- x1 = 250

-- Program segment containing real ARM64 Machine Instruction Words
-- Let's construct a sequence:
-- 1. ADD x2, x0, x1          => 0x8B010002
-- 2. SUB x3, x1, x0          => 0xCB000023
-- 3. STR x2, [sp, #8]        => 0xF9000BE2 (Store x2 into SP + 8)
-- 4. LDR x4, [sp, #8]        => 0xF9400BE4 (Load from SP + 8 into x4)
-- 5. CMP x4, #350            => 0xF105789F (Compare x4 with 350)
-- 6. B.EQ #8 (skip next sub) => 0x54000040 (If Z=1, jump PC by 8 bytes)
-- 7. SUB x4, x4, #50         => 0xD100C884 (If not equal, subtract 50)
-- 8. RET                     => 0xD65F03C0

local machine_code = {
    0x8B010002, -- ADD x2, x0, x1 (x2 = 100 + 250 = 350)
    0xCB000023, -- SUB x3, x1, x0 (x3 = 250 - 100 = 150)
    0xF9000BE2, -- STR x2, [sp, #8]
    0xF9400BE4, -- LDR x4, [sp, #8] (x4 = 350)
    0xF105789F, -- CMP x4, #350
    0x54000040, -- B.EQ +8 bytes (skips the SUB instruction, jumps straight to RET)
    0xD100C884, -- SUB x4, x4, #50 (should be skipped!)
    0xD65F03C0  -- RET
}

-- Write instructions into simulated instruction memory starting at PC=0x1000
local code_base = 0x1000
cpu.pc = code_base

-- We create an instruction mapping table for easy execution
local program_instructions = {}
for i, word in ipairs(machine_code) do
    local addr = code_base + (i - 1) * 4
    local decoded = arm64.decode_binary_word(word)
    program_instructions[addr] = decoded
end

print("=== ARM64 CPU Emulator Loading Completed ===")
print(string.format("Initial inputs: x0 = %d, x1 = %d", cpu:get_reg(0), cpu:get_reg(1)))

-- Execution Loop
local steps = 0
while true do
    local current_pc = cpu.pc
    local insn = program_instructions[current_pc]

    if not insn then
        print(string.format("\n[CPU HALTED] No instruction found at PC: 0x%08X", current_pc))
        break
    end

    local insn_desc = string.format("0x%08X: %s", current_pc, insn.op)
    if insn.op1 then insn_desc = insn_desc .. " " .. tostring(insn.op1) end
    if insn.op2 then insn_desc = insn_desc .. ", " .. tostring(insn.op2) end
    if insn.op3 then insn_desc = insn_desc .. ", " .. tostring(insn.op3) end

    steps = steps + 1
    local success, err = arm64.step(cpu, insn)
    if not success then
        print("\n[CPU ERROR]: " .. tostring(err))
        break
    end

    print_cpu_state(cpu, steps, insn_desc)

    if insn.op == "RET" then
        print("\n[CPU RETURN] execution successfully completed.")
        break
    end

    if steps > 20 then
        print("\n[CPU FORCE STOP] Too many steps (infinite loop safety limit reached).")
        break
    end
end
