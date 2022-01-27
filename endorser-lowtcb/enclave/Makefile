all:
	nasm -f elf64 entry.asm -o entry.o
	gcc -O4 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-asynchronous-unwind-tables -static-pie -nostdlib -m64 -mrdrnd endorser.c ../crypto/Hacl_Hash.c ../crypto/Hacl_Streaming_SHA2.c ../crypto/Hacl_P256.c entry.o -I. -I../include -I../crypto -I../crypto/include -o endorser.so
