/*
 * =====================================================================================
 *
 *       Filename:  callstack.c
 *
 *    Description:  演示栈在函数调用过程中发挥的关键作用
 *
 *        Version:  1.0
 *        Created:  2018年03月14日 21时15分20秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
int fun1(int a, char c)
{
    return c*a;
}

int fun2(int b)
{
    int c = 2;
    fun1(b + c,'d');
}
int main(void)
{
    
    int d = 10;
    fun2(d);
    return 0;
}

