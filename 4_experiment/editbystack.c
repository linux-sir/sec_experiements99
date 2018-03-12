/*
 * =====================================================================================
 *
 *       Filename:  editbystack.c
 *
 *    Description:  测试通过栈中变量位置关系，间接修改变量值
 *
 *        Version:  1.0
 *        Created:  2018年03月12日 21时22分12秒
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
    int a = 10;
    char b[5];
    *(int *)(&b + 1) = 20;
    printf("a = %d\n",a);
    return 0;
}

