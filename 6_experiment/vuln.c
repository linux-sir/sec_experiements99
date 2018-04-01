/*
 * =====================================================================================
 *
 *       Filename:  vuln.c
 *
 *    Description:  整型溢出示例
 *
 *        Version:  1.0
 *        Created:  2018年03月25日 16时14分32秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
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

