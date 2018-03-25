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

