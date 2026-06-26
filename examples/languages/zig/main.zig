const std = @import("std");

fn normalizeUser(name: []const u8, email: []const u8, active: bool) bool {
    const clean_name = std.mem.trim(u8, name, " ");
    const clean_email = std.mem.trim(u8, email, " ");
    const enabled = active and clean_email.len > 0;
    return enabled and clean_name.len > 0;
}
