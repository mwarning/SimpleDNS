all:
	gcc -Wall main.c -o main

fuzzer:
	clang -g -DFUZZER -O1 -fsanitize=fuzzer,address main.c -o fuzzer
