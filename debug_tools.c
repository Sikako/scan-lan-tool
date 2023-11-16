#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include "debug_tools.h"

extern uint8_t* buffer;

void print_buffer(uint8_t *buffer){
	for(int i=0; i<60; i++){
		printf("%02X ", buffer[i]);
		if ((i+1) % 16 == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}
