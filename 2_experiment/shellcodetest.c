/*
 * =====================================================================================
 *
 *       Filename:  shellcodetest.c
 *
 *    Description:  test for shellcode 
 *
 *        Version:  1.0
 *        Created:  2018年03月06日 20时53分17秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

char code[] = "\xb0\x01\x31\xdb\xcd\x80";
int main(int argc, char *argv[])
{
    int (*func)();
    func = (int (*)()) code;
    (int)(*func)();
    return 0;
}

