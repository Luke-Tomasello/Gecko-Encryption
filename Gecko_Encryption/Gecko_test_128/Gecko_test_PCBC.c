#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <time.h>
#include <assert.h> 
#include <conio.h>

#include "stdint.h"				// stanbdard types
#include "Gecko.h"				// main gecko include
#include "test_helpers.h"		// padding helpers
#include "Gecko_test.h"			// test functions
#include "Gecko_test_data.h"	// test data
#include "aes.h"				// AES stuff

void gt_HelloWorldPCBC(int test)
{
	GKO_state_t state;

	char hello[] = { 'H','e','l','l','o',' ','W','o','r','l','d','!','\0' };
	char working_buffer[32];
	uint32_t new_size;

	// TEST: Basic test of crypto. Make sure what goes into encrypt() comes out of decrypt()
	printf("TEST%d: Gecko Hello World! Test Setting up...\n", test);
	{
		memcpy(working_buffer, hello, sizeof(hello));						// make a copy for later test
		state.encryption_mode = GKO_mode_pcbc;		
		GKO_InitState(&state, gko_key, gko_iv);											
		new_size = GUTL_PadBlockRaw(working_buffer, sizeof(hello), 1);
		GKO_Encrypt(&state, working_buffer, new_size);		// call our encryptor
		state.encryption_mode = GKO_mode_pcbc;		
		GKO_InitState(&state, gko_key, gko_iv);											
		GKO_Decrypt(&state, working_buffer, new_size);						// call our decryptor with the new_size
		assert(memcmp(working_buffer, hello, sizeof(hello)) == 0);			// test that the decryptor output matches the original
		if (memcmp(working_buffer, hello, sizeof(hello)) == 0)				// tell the world about it
		{
			printf("TEST%d: Gecko \"%s\"  Test PASSED.\n", test, working_buffer);
			printf("**********************************\n\n");
		}
		else
		{
			printf("TEST%d: Gecko Hello World! Test Failed.\n", test);
			_getch();
			return;
		}
	}
}



// special secret data for the PCBC Sender/Receiver demonstration 
//	This is only a demonstration of PCBC functionality, not how keys are shared across apps/services, etc.
//	you will likely have your own mechanism. We perform the key exchange here only to demonstrate the separation of 
//	the Sender and Receiver
#if defined(_GKO256)
const uint8_t GKO_PCBC_TEST_SECRET_key[GKO_KEY_NELTS] = {	0xd2, 0xa6, 0xab, 0xf7, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 
								0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
#elif defined(_GKO192)
// we will add 8 bytes here for padding since a 24 bit key is not GKO_BLOCK_SIZE % 16
//	we will pad below
const uint8_t GKO_PCBC_TEST_SECRET_key[GKO_KEY_NELTS] = {	0x2d, 0x98, 0x10, 0xa3, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
								0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }; 
#elif defined(_GKO128)
const uint8_t GKO_PCBC_TEST_SECRET_key[GKO_KEY_NELTS] = { 0x60, 0x3d, 0xeb, 0x10, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif

const uint8_t GKO_PCBC_TEST_SECRET_iv[GKO_IV_BUFFER_SIZE] = 
{ 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5 };

#define PCBC_TEST_MAX_KEY 32		// we need to pad for 24byte keys to 32 bytes
#define PCBC_TEST_SET_KEYIV 0
#define PCBC_TEST_INIT 1
#define PCBC_TEST_DATA 2
#define PCBC_TEST_DONE 3
static void gt_CallHelloWorldPCBCReceiver(int mode, uint8_t _buff1[PCBC_TEST_MAX_KEY], uint8_t _buff2[GKO_IV_BUFFER_SIZE])
{
	// static to retain state across calls
	static GKO_state_t state;
	uint16_t new_size;
	// the Sender will send us the key and IV
	static uint8_t GKO_PCBC_TEST_SESSION_key[GKO_KEY_NELTS];
	// PCBC needs an IV. The GKO_PCBC_TEST_SESSION_iv is used to store this data, that's why it needs to be static, malloc'ed, etc.
	static uint8_t GKO_PCBC_TEST_SESSION_iv[GKO_IV_BUFFER_SIZE];
	uint8_t buff1[PCBC_TEST_MAX_KEY], buff2[GKO_IV_BUFFER_SIZE];

	switch (mode)
	{
	case PCBC_TEST_SET_KEYIV:
		if (GKO_KEY_NELTS == 24)	// special case for 192 bit keys
			memcpy(buff1, _buff1,PCBC_TEST_MAX_KEY);
		else
			memcpy(buff1, _buff1,GKO_KEY_NELTS);
		memcpy(buff2, _buff2,GKO_IV_BUFFER_SIZE);
		// okay, now we have the encrypted the session key and session iv with the secret key that we share with the Receiver
		state.encryption_mode = GKO_mode_pcbc;							// Set PCBC mode
		GKO_InitState(&state, GKO_PCBC_TEST_SECRET_key, GKO_PCBC_TEST_SECRET_iv);											
		GKO_Decrypt(&state, buff1, GKO_KEY_NELTS == 24 ? PCBC_TEST_MAX_KEY : GKO_KEY_NELTS);
		if (GKO_KEY_NELTS == 24)	
		{	// special case for 192 bit keys, unpack the 24 bytes from the 32 bytes
			new_size = GUTL_UnPadBlockRaw(buff1, PCBC_TEST_MAX_KEY);
			assert(new_size == GKO_KEY_NELTS);
		}
		memcpy(GKO_PCBC_TEST_SESSION_key, buff1, GKO_KEY_NELTS);
		GKO_Decrypt(&state, buff2, GKO_IV_BUFFER_SIZE);
		memcpy(GKO_PCBC_TEST_SESSION_iv, buff2, GKO_IV_BUFFER_SIZE);
		break;
	case PCBC_TEST_INIT:
		state.encryption_mode = GKO_mode_pcbc;							// Set PCBC mode
		GKO_InitState(&state, GKO_PCBC_TEST_SESSION_key, GKO_PCBC_TEST_SESSION_iv);											
		break;
	case PCBC_TEST_DATA:
	{
		uint16_t cx;
		memcpy(buff1, _buff1,GKO_BLOCK_SIZE);
		// okay, wr're ready for data
		GKO_Decrypt(&state, buff1, GKO_BLOCK_SIZE);
		new_size = GUTL_UnPadBlockRaw(buff1, GKO_BLOCK_SIZE);			// cleanup the buffer
		for (cx = 0; cx < new_size; cx++)								// print the output
			printf("%c", buff1[cx]);
	}
	break;
	case PCBC_TEST_DONE:
		printf("\n\n");
		break;

	}
}

void gt_HelloWorldPCBCSender(int test)
{
	GKO_state_t state;
	uint16_t new_size;
	int ix;

	// we'll fill in the session key dynamically and share it with the Receiver
	//	We can't use GKO_KEY_NELTS here for the case when the key is 24 bytes
	//	we will need to pad it out to 32 bytes (PCBC_TEST_MAX_KEY)
	static uint8_t GKO_PCBC_TEST_SESSION_key[PCBC_TEST_MAX_KEY];	
	static uint8_t GKO_PCBC_TEST_SESSION_iv[GKO_IV_BUFFER_SIZE];
	uint8_t session_key_buf[PCBC_TEST_MAX_KEY], session_iv_buf[GKO_IV_BUFFER_SIZE];
	char working_buffer[sizeof(Perrault) + 16 + 1];							// PCBC mode wants GKO_BLOCK_SIZE % 16 +1 for sentinel 

	printf("TEST%d: Gecko PCBC 'Send Receive' Test Setting up...\n", test);
	working_buffer[sizeof(Perrault) + 16] = 0x88;							// sentinel (sanity check)

	// first we will generate an IV for this PCBC session.
	for (ix = 0; ix < GKO_IV_BUFFER_SIZE; ix++)
		GKO_PCBC_TEST_SESSION_iv[ix] = (uint8_t)rand() % 256;

	// now we will generate a session key for this PCBC session.
	for (ix = 0; ix < GKO_KEY_NELTS; ix++)
		GKO_PCBC_TEST_SESSION_key[ix] = (uint8_t)rand() % 256;

	// make copies for our Receiver
	memcpy(session_key_buf,GKO_PCBC_TEST_SESSION_key,GKO_KEY_NELTS);
	memcpy(session_iv_buf, GKO_PCBC_TEST_SESSION_iv, GKO_IV_BUFFER_SIZE);

	// okay, now we encrypted the session key and session iv with the secret key that we share with the Receiver
	state.encryption_mode = GKO_mode_pcbc;															// Set PCBC mode
	GKO_InitState(&state, GKO_PCBC_TEST_SECRET_key, GKO_PCBC_TEST_SECRET_iv);										
	// pad the data. We need this in the case of 192bit keys or 24 bytes
	//	which is not GKO_BLOCK_SIZE % 16
	new_size = GUTL_PadBlockRaw(session_key_buf, GKO_KEY_NELTS, 0);	// pad the data to 'block size'
	GKO_Encrypt(&state, session_key_buf, new_size);
	// iv is always GKO_BLOCK_SIZE % 16, so no need to pad
	GKO_Encrypt(&state, session_iv_buf, GKO_IV_BUFFER_SIZE);

	// Okay, send the session data to our Receiver
	gt_CallHelloWorldPCBCReceiver(PCBC_TEST_SET_KEYIV, session_key_buf, session_iv_buf);

	// tell our Receiver to also init
	gt_CallHelloWorldPCBCReceiver(PCBC_TEST_INIT, NULL, NULL);

	// okay! Ready to send data
	memcpy(working_buffer, Perrault, strsize(Perrault));				// make a copy for later test

	// the reciever now has the new session key and IV.
	// We will now reinit with the session data
	state.encryption_mode = GKO_mode_pcbc;								// Set PCBC mode
	GKO_InitState(&state, GKO_PCBC_TEST_SESSION_key, GKO_PCBC_TEST_SESSION_iv);												

	new_size = GUTL_PadBlockRaw(working_buffer, strsize(Perrault), 1);	// pad the data to 'block size'
	for (ix = 0; ix < new_size; ix += GKO_BLOCK_SIZE)
	{
		GKO_Encrypt(&state, &working_buffer[ix], GKO_BLOCK_SIZE);
		gt_CallHelloWorldPCBCReceiver(PCBC_TEST_DATA, &working_buffer[ix], NULL);
	}

	// tell our Receiver we are done
	gt_CallHelloWorldPCBCReceiver(PCBC_TEST_DONE, NULL, NULL);

	assert(working_buffer[sizeof(Perrault) + 16] == (char)0x88);			// just sanity checking

	printf("TEST%d: Gecko PCBC 'Send Receive' Test complete.\n", test);
	printf("**********************************\n\n");
}



