/*
 * =====================================================================================
 *
 *       Filename:  shellcode.c
 *
 *    Description:  shellcode
 *
 *        Version:  1.0
 *        Created:  2018年03月05日 21时18分49秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <unistd.h>
int main(void)
{
    char *name[2] ;
    name[0] = "/bin/sh";
    name[1] = NULL;
    execve(name[0], name, NULL);
    return 0;
}
