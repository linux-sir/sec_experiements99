/*
 * =====================================================================================
 *
 *       Filename:  stack.c
 *
 *    Description:  stack 漏洞程序
 *
 *        Version:  1.0
 *        Created:  2018年03月05日 21时23分50秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


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
