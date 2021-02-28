#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
ctoi(char c){
  // 0-9
  if ( c >= 48 && c <= 57) return c - 48;
  
  // A-F
  if (c >= 65 && c <= 70) return c - 55;
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	
	// Encode AccountName, Issuer & create encoding ptr for the secret
	char * accountName_encoded = urlEncode(accountName);
	char * issuer_encoded = urlEncode(issuer);
	char secret_encoded[16];
	
	// Convert secret_hex to uint8_t data
	uint8_t data[10];
	
	int i;
	for ( i = 0; i < 19; i += 2 ) {
	  
	  data[i / 2] = ctoi(secret_hex[i + 1]) + 16 * ctoi(secret_hex[i]);
	}
	
	int numBytesEncoded = 0;
	numBytesEncoded = base32_encode(data, 10, secret_encoded, 17);
	
	char URI[512];
	snprintf((const char *)URI, 512, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName_encoded, issuer_encoded, secret_encoded);
	displayQRcode(URI);

	return (0);
}
