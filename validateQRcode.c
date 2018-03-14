#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include "lib/sha1.h"

// converts between HEX to bytes
// scans the input and puts it in results
void 
converter(char* secret, uint8_t *result){
	int i;
	
	for (i = 0; i < (strlen(secret) / 2); i++) 
    {
        sscanf(secret + 2*i, "%02x", &result[i]);       
    }
}


// HMAC function with SHA1 hashing algo
void 
HMAC_SHA1(uint8_t * key, uint8_t * m, uint8_t * hmac_result)
{
	//pad to 64 bytes
	int SHA1_Size = 64;
	uint8_t newKey[SHA1_Size];

	int i;
	for(i=0;i<SHA1_Size;i++){
		if (i < 10)
			newKey[i] = key[i];
		else
			newKey[i] = 0x00;
	}

	// array for holding inner and outer pad

	uint8_t K_opad[SHA1_Size];
	uint8_t K_ipad[SHA1_Size];

	// XOR key with i_pad and o_pad
	for(i=0;i<SHA1_Size;i++){
		K_opad[i] = 0x5c ^ newKey[i];
		K_ipad[i] = 0x36 ^ newKey[i];			
	}

	// hash the innner value
	SHA1_INFO ctx_in;
	uint8_t hash_in[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx_in);
	sha1_update(&ctx_in, K_ipad, SHA1_Size);
	sha1_update(&ctx_in, m,8);
	sha1_final(&ctx_in, hash_in);


	// hash the inner hashed value
	SHA1_INFO ctx_out;
	sha1_init(&ctx_out);
	sha1_update(&ctx_out, K_opad, SHA1_Size);
	sha1_update(&ctx_out, hash_in,SHA1_DIGEST_LENGTH);
	sha1_final(&ctx_out, hmac_result);

	return;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string, int C )
{
	//hex to byte conversion
	uint8_t byteArr[10];
	converter(secret_hex, byteArr);

	uint8_t counter[8];
	int i;
	for (i = 7; i >= 0; i--){
		counter[i] = C;
		C = C >> 8;
	}	

	// put the results in the hmac_results array
	uint8_t hmac_result[100];
	HMAC_SHA1(byteArr, counter ,hmac_result);

	//truncating to 6 digits
	int offset   =  hmac_result[19] & 0xf;
	int bin_code = (hmac_result[offset]  & 0x7f) << 24
	   | (hmac_result[offset+1] & 0xff) << 16
	   | (hmac_result[offset+2] & 0xff) <<  8
	   | (hmac_result[offset+3] & 0xff) ;


	   // return the result
	return (bin_code%1000000 == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t byteArr[10];
	converter(secret_hex, byteArr);

	// period = 30 seconds
	long X = time(NULL)/30;


	// return the validated result
	return (validateHOTP(secret_hex,TOTP_string,X));

}


int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value, 1) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
