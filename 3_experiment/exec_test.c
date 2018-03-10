/*
 * =====================================================================================
 *
 *       Filename:  exec_test.c
 *
 *    Description:  系统调用execve函数返回Shell
 *
 *        Version:  1.0
 *        Created:  2018年03月06日 21时57分01秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <unistd.h>
#include <stdlib.h>

char *buf[] = {"/bin/sh", NULL};
int main(void)
{
    execve("/bin/sh", buf,0);
    return 0;
}
