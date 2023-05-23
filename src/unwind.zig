const std = @import("std");

pub fn decodeInstructions(
    source: anytype,
    starting_offset: usize,
    cie: CieHeader,
    entry_size: usize,
    instructions: *std.ArrayList(Instruction),
) !void {
    const end_offset = starting_offset + entry_size;
    while (try source.seekableStream().getPos() < end_offset) {
        const opcode_byte = try source.reader().readByte();
        const opcode = blk: {
            const opcode_high = opcode_byte & opcode_high_mask;
            const raw_opcode = if (opcode_high != 0)
                opcode_high
            else
                opcode_byte;

            break :blk std.meta.intToEnum(OpCode, raw_opcode) catch {
                return error.UnsupportedOpCode;
            };
        };

        const instruction: Instruction = blk: {
            switch (opcode) {
                .nop => break :blk .nop,
                .advance_loc => {
                    const factored_offset = opcode_byte & opcode_low_mask;
                    const offset = factored_offset * cie.code_alignment_factor;
                    break :blk .{ .advance_loc = offset };
                },
                .advance_loc1 => {
                    const factored_offset = try source.reader().readByte();
                    const offset = factored_offset * cie.code_alignment_factor;
                    break :blk .{ .advance_loc1 = offset };
                },
                .advance_loc2 => {
                    const factored_offset = try source.reader().readIntLittle(u16);
                    const offset = factored_offset * cie.code_alignment_factor;
                    break :blk .{ .advance_loc2 = offset };
                },
                .advance_loc4 => {
                    const factored_offset = try source.reader().readIntLittle(u32);
                    const offset = factored_offset * cie.code_alignment_factor;
                    break :blk .{ .advance_loc4 = offset };
                },
                .offset => {
                    const register = opcode_byte & opcode_low_mask;
                    const factored_offset = try std.leb.readULEB128(i64, source.reader());
                    const offset = factored_offset * cie.data_alignment_factor;
                    break :blk .{ .offset = .{ .register = register, .offset = offset } };
                },
                .def_cfa => {
                    const register = try std.leb.readULEB128(u8, source.reader());
                    const offset = try std.leb.readULEB128(u64, source.reader());
                    break :blk .{ .def_cfa = .{ .register = register, .offset = offset } };
                },
                .def_cfa_register => {
                    const register = try std.leb.readULEB128(u8, source.reader());
                    break :blk .{ .def_cfa_register = register };
                },
                .def_cfa_offset => {
                    const offset = try std.leb.readULEB128(u64, source.reader());
                    break :blk .{ .def_cfa_offset = offset };
                },
            }
        };

        try instructions.append(instruction);
    }
}

pub fn executeInstructions(instructions: []const Instruction, table: *std.ArrayList(CfiRow)) !void {
    var previous_row = table.items[0];
    var offset: usize = 0;
    while (offset < instructions.len) {
        var row = previous_row;
        switch (instructions[offset]) {
            .advance_loc,
            .advance_loc1,
            .advance_loc2,
            .advance_loc4,
            => |amount| {
                row.location += amount;
                offset += 1;
            },
            else => {},
        }

        const executed_count = try executeInstructionsForRow(instructions[offset..], &row);
        try table.append(row);

        previous_row = row;
        offset += executed_count;
    }
}

pub fn executeAllInstructionsForRow(instructions: []const Instruction, row: *CfiRow) !void {
    const executed_count = try executeInstructionsForRow(instructions, row);
    if (executed_count != instructions.len) {
        return error.UnexpectedInstruction;
    }
}

fn executeInstructionsForRow(
    instructions: []const Instruction,
    row: *CfiRow,
) !usize {
    var executed_count: usize = 0;

    for (instructions) |instruction| {
        switch (instruction) {
            .nop => {},
            .advance_loc,
            .advance_loc1,
            .advance_loc2,
            .advance_loc4,
            => break,
            .offset => |operands| {
                row.registers[operands.register] = .{ .offset = operands.offset };
            },
            .def_cfa => |cfa| {
                row.cfa = .{ .register = cfa.register, .offset = cfa.offset };
            },
            .def_cfa_register => |register| {
                row.cfa.register = register;
            },
            .def_cfa_offset => |offset| {
                row.cfa.offset = offset;
            },
        }

        executed_count += 1;
    }

    return executed_count;
}

pub const register_count = 16;
pub const CfiRow = struct {
    location: u64,
    cfa: CfaRule,
    registers: [column_count]RegisterRule = .{.undefined} ** CfiRow.column_count,

    pub const ra_index = 16;
    const column_count = register_count + 1;
};

pub const CfaRule = struct {
    register: u8,
    offset: u64,

    pub fn format(
        self: CfaRule,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;

        const register = register_name[self.register];

        var offset: [1 + std.math.max(@typeInfo(@TypeOf(self.offset)).Int.bits, 1)]u8 = undefined;
        const offset_len = std.fmt.formatIntBuf(&offset, self.offset, 10, .lower, .{});

        const width = register.len + 1 + offset_len;
        const fill_width = if (options.width) |min_width| min_width else 0;
        const padding = if (width < fill_width) fill_width - width else 0;

        try std.fmt.format(writer, "{s}+{s}", .{ register, offset[0..offset_len] });
        try writer.writeByteNTimes(options.fill, padding);
    }
};

const RegisterRuleTag = enum {
    undefined,
    // same_value,
    offset,
};

pub const RegisterRule = union(RegisterRuleTag) {
    undefined,
    offset: i64,

    pub fn format(
        self: RegisterRule,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;

        const fill_width = if (options.width) |min_width| min_width else 0;

        switch (self) {
            .undefined => {
                const padding = if (1 < fill_width) fill_width - 1 else 0;
                try writer.writeByte('u');
                try writer.writeByteNTimes(options.fill, padding);
            },
            .offset => |amount| {
                var amount_string: [1 + std.math.max(@typeInfo(@TypeOf(amount)).Int.bits, 1)]u8 = undefined;
                const amount_len = std.fmt.formatIntBuf(&amount_string, amount, 10, .lower, .{});
                const sign = if (amount < 0) "" else "+";
                const width = 1 + sign.len + amount_len;
                const padding = if (width < fill_width) fill_width - width else 0;
                try std.fmt.format(writer, "c{s}{s}", .{
                    sign,
                    amount_string[0..amount_len],
                });
                try writer.writeByteNTimes(options.fill, padding);
            },
        }
    }
};

pub const CieHeader = struct {
    length: u32,
    length_size: u32 = @sizeOf(u32),
    id: u32,
    version: u8,
    augmentation: []const u8,
    pointer_size: u8,
    segment_size: u8,
    code_alignment_factor: u64,
    data_alignment_factor: i64,
    return_address_column: u8,

    pub fn sizeInFile(self: CieHeader) usize {
        return self.length + self.length_size;
    }

    pub fn deinit(self: CieHeader, allocator: std.mem.Allocator) void {
        allocator.free(self.augmentation);
    }

    pub fn parse(allocator: std.mem.Allocator, source: anytype) !CieHeader {
        const length = try readLength(source);
        const id = try source.reader().readIntLittle(u32);
        const version = try source.reader().readByte();

        const augmentation = blk: {
            var buffer = std.ArrayList(u8).init(allocator);
            errdefer buffer.deinit();
            try source.reader().readUntilDelimiterArrayList(&buffer, 0, std.math.maxInt(usize));
            break :blk try buffer.toOwnedSlice();
        };
        if (augmentation.len > 0) {
            return error.AugmentationNotSupported;
        }

        const pointer_size = try source.reader().readByte();
        const segment_size = try source.reader().readByte();
        const code_alignment_factor = try std.leb.readULEB128(u64, source.reader());
        const data_alignment_factor = try std.leb.readILEB128(i64, source.reader());
        const return_address_column = try std.leb.readULEB128(u8, source.reader());

        return .{
            .length = length,
            .id = id,
            .version = version,
            .augmentation = augmentation,
            .pointer_size = pointer_size,
            .segment_size = segment_size,
            .code_alignment_factor = code_alignment_factor,
            .data_alignment_factor = data_alignment_factor,
            .return_address_column = return_address_column,
        };
    }
};

pub const FdeHeader = struct {
    length: u32,
    length_size: u32 = @sizeOf(u32),
    cie_offset: u32,
    location_begin: u64,
    location_end: u64,

    pub fn sizeInFile(self: FdeHeader) usize {
        return self.length + self.length_size;
    }

    pub fn parse(source: anytype) !FdeHeader {
        const length = try readLength(source);
        const cie_offset = try source.reader().readIntLittle(u32);
        const location_begin = try source.reader().readIntLittle(u64);
        const address_range = try source.reader().readIntLittle(u64);
        const location_end = location_begin + address_range;

        return .{
            .length = length,
            .cie_offset = cie_offset,
            .location_begin = location_begin,
            .location_end = location_end,
        };
    }
};

pub const Fde = struct {
    header: FdeHeader,
    table: std.ArrayList(CfiRow),

    pub fn deinit(self: Fde) void {
        self.table.deinit();
    }

    pub fn parse(allocator: std.mem.Allocator, source: anytype, cie: CieHeader, first_row_template: CfiRow) !Fde {
        const begin = try source.seekableStream().getPos();
        const header = try FdeHeader.parse(source);

        var table = std.ArrayList(CfiRow).init(allocator);
        errdefer table.deinit();

        var first_row = first_row_template;
        first_row.location = header.location_begin;
        try table.append(first_row);

        var instructions = std.ArrayList(Instruction).init(allocator);
        defer instructions.deinit();
        try decodeInstructions(source, begin, cie, header.sizeInFile(), &instructions);
        try executeInstructions(instructions.items, &table);

        return .{
            .header = header,
            .table = table,
        };
    }

    pub fn addressLessThan(_: void, lhs: Fde, rhs: Fde) bool {
        return lhs.header.location_begin < rhs.header.location_begin;
    }
};

pub fn printFde(stream: anytype, fde: Fde) !void {
    try stream.writer().print("{X:0>16} FDE cie={X:0>8} pc={X:0>16}..{X:0>16}\n", .{
        fde.header.length,
        fde.header.cie_offset,
        fde.header.location_begin,
        fde.header.location_end,
    });

    const column_titles = "LOC              CFA      " ++ comptime generateRegisterTitles(register_count) ++ "\n";
    try stream.writer().writeAll(column_titles);

    for (fde.table.items) |row| {
        try printCfiRow(stream, row);
    }

    try stream.writer().writeByte('\n');
}

pub fn printCfiRow(stream: anytype, row: CfiRow) !void {
    try stream.writer().print("{X:0>16} {: <8} ", .{ row.location, row.cfa });

    for (row.registers) |register| {
        try stream.writer().print("{: <5} ", .{register});
    }

    try stream.writer().writeByte('\n');
}

fn generateRegisterTitles(comptime count: usize) []const u8 {
    @setEvalBranchQuota(register_count);
    return generateRegisterTitlesHelper(0, count);
}

pub const register_name = [_][]const u8{
    "rsi",
    "rdi",
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "ra",
};

fn generateRegisterTitlesHelper(comptime register: usize, comptime count: usize) []const u8 {
    return comptime if (register == count)
        ""
    else
        std.fmt.comptimePrint("{s: <5} ", .{register_name[register]}) ++ generateRegisterTitlesHelper(register + 1, count);
}

fn readLength(source: anytype) !u32 {
    const length = try source.reader().readIntLittle(u32);
    if (length == std.math.maxInt(u32)) {
        return error.ExtendedLengthNotSupported;
    }

    return length;
}

const opcode_high_mask = 0b11 << 6;
const opcode_low_mask = 0xFF ^ opcode_high_mask;

const OpCode = enum(u8) {
    nop = 0x00,
    advance_loc = 0x1 << 6,
    offset = 0x2 << 6,
    // restore = 0x3 << 6,
    // set_loc = 0x01,
    advance_loc1 = 0x02,
    advance_loc2 = 0x03,
    advance_loc4 = 0x04,
    // offset_extended = 0x05,
    // restore_extended = 0x06,
    // undefined = 0x07,
    // same_value = 0x08,
    // register = 0x09,
    // remember_state = 0x0A,
    // restore_state = 0x0B,
    def_cfa = 0x0C,
    def_cfa_register = 0x0D,
    def_cfa_offset = 0x0E,
};

pub const Instruction = union(OpCode) {
    nop,
    advance_loc: u64,
    advance_loc1: u64,
    advance_loc2: u64,
    advance_loc4: u64,
    offset: struct { register: u8, offset: i64 },
    def_cfa: struct { register: u8, offset: u64 },
    def_cfa_register: u8,
    def_cfa_offset: u64,
};
