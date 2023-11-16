CC = gcc

main: main.o
	$(CC) -o main main.o
main.o: main.c
	$(CC) -c main.c


.INTERMEDIATE: main.o