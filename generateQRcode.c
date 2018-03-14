#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"


// converts between HEX to bytes
// scans the input and puts it in results
void converter(char* secret, uint8_t *result){
	int i;
	
	// goes upto strlen/2 as 1 byte = 2 hex char
	for (i = 0; i < (strlen(secret) / 2); i++) 
    {
        sscanf(secret + 2*i, "%02x", &result[i]);       
    }
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

	const char * encodingName = issuer;
	const char * encodingAccount = accountName;

	const char * e_Name;
	const char * e_Issuer;

	e_Issuer = urlEncode(encodingName);
	e_Name = urlEncode(encodingAccount);

	// as all the secret keys vals will be provided in 20-chars so no padding is done yet
	// waiting for piazza


	// convert to byte array 
	// 20 Hex char = 10 bytes
	// 2 hex char = 1 byte

	uint8_t byteArr[10];
	converter(secret_hex, byteArr);

	// for debugging: printf("byteArr: %u\n", byteArr);

	// encode
	// store the encoded stuff in the result array

    char result[100];
    base32_encode(byteArr, 10, result, 100);

    // for debugging printf("%s\n", result);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
    
    char outpath1[1000];
    char outpath2[1000];
    // HOTP
	sprintf(outpath1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", e_Name, e_Issuer, result);
	// TOTP
    sprintf(outpath2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", e_Name, e_Issuer, result);

    // Displays HOTP
	displayQRcode(outpath1);
	// Displays TOTP
	displayQRcode(outpath2);

	return (0);
}
