#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include "lib/sha1.h"

int
ctoi(char c){
  // 0-9
  if ( c >= 48 && c <= 57) return c - 48;
  
  // A-F
  if (c >= 65 && c <= 70) return c - 55;
}

void
HMAC(uint8_t * key_ipad, uint8_t * key_opad, uint8_t * msg, uint8_t * sha_out)
{
   // Block size for sha1 = 64B
  SHA1_INFO 		ctx;
  uint8_t 		sha_in[SHA1_DIGEST_LENGTH];
  sha1_init(&ctx);
  sha1_update(&ctx, key_ipad, 64);
  sha1_update(&ctx, msg, 8);
  sha1_final(&ctx, sha_in);
  
  SHA1_INFO 		ctx2;
  sha1_init(&ctx2);
  sha1_update(&ctx2, key_opad, 64);
  sha1_update(&ctx2, sha_in, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx2, sha_out);

  return;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
  // Convert secret_hex
  uint8_t data[10];
  
  int i;
  for ( i = 0; i < 19; i += 2 ) {	  
    data[i / 2] = ctoi(secret_hex[i + 1]) + 16 * ctoi(secret_hex[i]);
  }
  
  // Prepare key ^ i/opad
  unsigned char key_ipad[64];
  unsigned char key_opad[64];
  
  for ( i = 0; i < 10; i++) {
   key_ipad[i] = data[i];
   key_opad[i] = data[i];
  }
  
  for ( i = 10; i < 64; i++) {
   key_ipad[i] = 0x00;
   key_opad[i] = 0x00;
  }
  
  // Bitwise XOR byte by byte
  for ( i = 0; i < 64; i++) {
   key_ipad[i] = key_ipad[i] ^ 0x36;
   key_opad[i] = key_opad[i] ^ 0x5c;
  }
  
  uint64_t period = time(NULL) / 30;
  uint8_t m[8];
  
  for ( i = 7; i >= 0; i-- ){
    m[i] = period;
    period = period >> 8;
  }
  
  // sha_out will hold the HMAC calc
  uint8_t 		sha_out[SHA1_DIGEST_LENGTH];
  
  HMAC(key_ipad, key_opad, m, sha_out);
  
  // Truncation
  int offset = sha_out[19] & 0xf;
  int bin = ( sha_out[offset] & 0x7f ) << 24 |
	    ( sha_out[offset + 1] & 0xff ) << 16 |
	    ( sha_out[offset + 2] & 0xff ) << 8 |
	    ( sha_out[offset + 3] & 0xff );

  int retval = (int)bin % (int)(pow(10,6)); 	
  printf("%d\n", retval);
  if ( retval == atoi(TOTP_string) ) return 1;
  else return 0;
  
  //return (0);
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
