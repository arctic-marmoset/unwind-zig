const std = @import("std");

const unwind = @import("unwind.zig");

const panic_stack = @embedFile("stack.mem");

const panic_pc = 0x209cf1;
const stack_offset = 0x7f054b0;
const panic_registers = [unwind.register_count]u64{
    0,
    1,
    0,
    0x20b010,
    0x20b001,
    0,
    0x7f06120,
    0x7f054b0,
    0,
    0x2d0,
    0x10,
    0,
    0x15,
    0,
    0x7f05560,
    0,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    const cwd = std.fs.cwd();
    const debug_info = try std.debug.readElfDebugInfo(allocator, try cwd.openFile("test/input/kernel.elf", .{}));
    var stream = std.io.fixedBufferStream(debug_info.dwarf.debug_frame.?);

    const cie_header_offset = 0;
    const cie_header = try unwind.CieHeader.parse(allocator, &stream);
    defer cie_header.deinit(allocator);
    var init_instructions = std.ArrayList(unwind.Instruction).init(allocator);
    defer init_instructions.deinit();
    try unwind.decodeInstructions(&stream, cie_header_offset, cie_header, cie_header.sizeInFile(), &init_instructions);
    const first_row_template: unwind.CfiRow = blk: {
        var row: unwind.CfiRow = .{ .location = undefined, .cfa = undefined };
        try unwind.executeAllInstructionsForRow(init_instructions.items, &row);
        break :blk row;
    };

    var entries = std.ArrayList(unwind.Fde).init(allocator);
    defer entries.deinit();
    while (try stream.getPos() < try stream.getEndPos()) {
        const fde = try unwind.Fde.parse(allocator, &stream, cie_header, first_row_template);
        try entries.append(fde);
    }
    std.sort.sort(unwind.Fde, entries.items, {}, unwind.Fde.addressLessThan);

    for (entries.items) |entry| {
        try unwind.printFde(std.io.getStdOut(), entry);
    }

    var pc: u64 = panic_pc;
    var registers = panic_registers;
    while (try getReturnAddress(entries.items, pc, &registers, stack_offset, panic_stack)) |ra| : (pc = ra) {
        std.debug.print("return address: {X:0>8}\n", .{ra});
    }
}

fn getReturnAddress(
    entries: []const unwind.Fde,
    pc: u64,
    registers: []u64,
    stack_begin: u64,
    stack: []const u8,
) !?u64 {
    const entry = blk: {
        for (entries) |entry| {
            if (pc >= entry.header.location_begin and pc <= entry.header.location_end) {
                break :blk entry;
            }
        }
        return null;
    };

    const row = blk: {
        var previous_row: unwind.CfiRow = undefined;
        for (entry.table.items) |row| {
            if (pc < row.location) {
                break;
            }
            previous_row = row;
        }
        break :blk previous_row;
    };

    const frame_address = registers[row.cfa.register] + row.cfa.offset;
    const ra_rule = row.registers[unwind.CfiRow.ra_index];

    const ra_address = if (ra_rule.offset < 0)
        frame_address - @intCast(u64, -ra_rule.offset)
    else
        frame_address + @intCast(u64, ra_rule.offset);

    const ra_stack_offset = ra_address - stack_begin;
    var stream = std.io.fixedBufferStream(stack);
    try stream.seekTo(ra_stack_offset);
    const ra = try stream.reader().readIntLittle(u64);

    registers[7] = frame_address;

    return ra;
}
