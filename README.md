# Unwind

Hacky stack unwinding using DWARF unwind info. This was created specifically for
my hobby OS so it could produce nice stacktraces on panic (for easier debugging).

Zig stdlib now implements DWARF unwinding and is much more robust than this one,
so this repo is now archived.
