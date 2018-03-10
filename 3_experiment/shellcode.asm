global _start
_start:
mov eax,0
mov edx,0
push edx
push "/sh"
push "/bin"
mov ebx,esp
xor eax,eax
mov al,0Bh
int 80h

