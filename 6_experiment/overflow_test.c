/*
 * =====================================================================================
 *
 *       Filename:  overflow_test.c
 *
 *    Description:  测试整型溢出的范围
 *
 *        Version:  1.0
 *        Created:  2018年04月01日 22时36分28秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
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

