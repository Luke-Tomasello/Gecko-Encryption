#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h> 
#include <conio.h>

#include "stdint.h"			// standard types
#include "Gecko.h"			// main gecko include
#include "test_helpers.h"	// padding helper
#include "aes.h"			// main aes include

// Gecko keys and IV
#if defined(_GKO256)
const uint8_t GKO_key[] = {	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 
								0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
//const int GKO_key256Nelts = (sizeof(GKO_key256) / sizeof(GKO_key256[0]));
#elif defined(_GKO192)
const uint8_t GKO_key[] = {	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
								0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
#elif defined(_GKO128)
const uint8_t GKO_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif

// AES keys and IV
#if defined(AES256)
uint8_t aes_key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
#elif defined(AES192)
uint8_t aes_key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
#elif defined(AES128)
uint8_t aes_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif

uint8_t aes_iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
const uint8_t GKO_iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };


void gt_AESvsGKO_Size(int test)
{
	GKO_state_t state;
	struct AES_ctx ctx;
	char hello[] = { 'H','e','l','l','o',' ','W','o','r','l','d','!','\0' };
	char working_buffer[32];
	uint32_t new_size;

	// GKO - do nothing. Just used for determining size of AES vs GKO
	//	see gecko.obj in /Size directory
	memcpy(working_buffer, hello, sizeof(hello));				
	new_size = GUTL_PadBlockRaw(working_buffer, sizeof(hello), 1);
	state.encryption_mode = GKO_mode_cbc;						
	GKO_InitState(&state, GKO_key, GKO_iv);											
	GKO_Encrypt(&state, working_buffer, new_size);				
	state.encryption_mode = GKO_mode_cbc;						
	GKO_InitState(&state, GKO_key, GKO_iv);											
	GKO_Decrypt(&state, working_buffer, new_size);				

	// AES - do nothing. Just used for determining size of AES vs GKO
	//	see aes.obj in /Size directory
	memcpy(working_buffer, hello, sizeof(hello));
	new_size = GUTL_PadBlockRaw(working_buffer, sizeof(hello), 1);
	AES_init_ctx_iv(&ctx, aes_key, aes_iv);						
	AES_CBC_encrypt_buffer(&ctx, working_buffer,new_size);		
	AES_init_ctx_iv(&ctx, aes_key, aes_iv);						
	AES_CBC_decrypt_buffer(&ctx, working_buffer,new_size);		
}

void main()
{
	
	printf("\nAll test comparisons are Gecko %s vs AES %s.\n",
		(GKO_KEY_NELTS == 16 ? "128" : (GKO_KEY_NELTS == 24 ? "192" : "256")),
		(GKO_KEY_NELTS == 16 ? "128" : (GKO_KEY_NELTS == 24 ? "192" : "256")));
	printf("**********************************\n\n");

	// run the single mode test
	gt_AESvsGKO_Size(1);

	printf("Please check the /size folder for determining size of AES vs GKO in CBC mode\n");
	printf("press any key to close window\n");
	_getch();
	return ;
}
