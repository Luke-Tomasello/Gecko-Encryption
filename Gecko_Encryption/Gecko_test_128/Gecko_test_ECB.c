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

void gt_HelloWorldECB(int test)
{
	GKO_state_t state;

	char hello[] = { 'H','e','l','l','o',' ','W','o','r','l','d','!','\0' };
	char working_buffer[GKO_BLOCK_SIZE + 1];								// CTR mode wants 16 +1 for sentinel 
	uint16_t new_size;

	working_buffer[GKO_BLOCK_SIZE] = 0x88;								// sentinel for sanity check

	// TEST: Basic test of crypto. Make sure what goes into encrypt() comes out of decrypt()
	printf("TEST%d: Gecko Hello World! ECB Test Setting up...\n", test);
	{
		memcpy(working_buffer, hello, sizeof(hello));						// make a copy for later test

		state.encryption_mode = GKO_mode_ecb;								// Set ECB mode.  
		GKO_InitState(&state, gko_key, gko_iv);																					
		new_size = GUTL_PadBlockRaw(working_buffer, sizeof(hello), 1);
		GKO_Encrypt(&state, working_buffer, new_size);						// call our encryptor

		state.encryption_mode = GKO_mode_ecb;								// Set ECB mode
		GKO_InitState(&state, gko_key, gko_iv);																							// freshen state for decrypt
		GKO_Decrypt(&state, working_buffer, new_size);						// call our decryptor with new size
		new_size =															// size of the buffer after removing padding. 
			GUTL_UnPadBlockRaw(working_buffer, new_size);					// Use this new_size for realloc, i/o, etc.
		assert(memcmp(working_buffer, hello, sizeof(hello)) == 0);			// test that the decryptor output matches the original
		assert(working_buffer[GKO_BLOCK_SIZE] == (char)0x88);				// just sanity checking
		if (memcmp(working_buffer, hello, sizeof(hello)) == 0)				// tell the world about it
		{
			printf("TEST%d: Gecko \"%s\"  ECB Test PASSED.\n", test, working_buffer);
			printf("**********************************\n\n");
		}
		else
		{
			printf("TEST%d: Gecko Hello World! ECB Test Failed.\n", test);
			_getch();
			return;
		}
	}
}

static int _gt_HelloWorldECB_GKO(int test)
{
	GKO_state_t state; 
	char working_buffer[GKO_BLOCK_SIZE * 8 + 1];						// ECB mode wants 16 bytes * 8 = 128 + 1 for sentinel 
	uint16_t new_size;

	// copy the test data to a working buffer. 
	memcpy(working_buffer, TheTruth, strsize(TheTruth));				// make a copy for later test
	working_buffer[GKO_BLOCK_SIZE * 8] = 0x88;							// sentinel for sanity check

	state.encryption_mode = GKO_mode_ecb;								// Set ECB mode
	GKO_InitState(&state, gko_key, NULL);
	new_size = GUTL_PadBlockRaw(working_buffer, strsize(TheTruth), 1);
	GKO_Encrypt(&state, working_buffer, new_size);						// call our encryptor

	state.encryption_mode = GKO_mode_ecb;								// Set ECB mode
	GKO_InitState(&state, gko_key, NULL);
	GKO_Decrypt(&state, working_buffer, new_size);						// call our decryptor with new size
	assert(memcmp(working_buffer, TheTruth, strsize(TheTruth)) == 0);	// test that the decryptor output matches the original
	assert(working_buffer[GKO_BLOCK_SIZE * 8] == (char)0x88);			// just sanity checking
	if (memcmp(working_buffer, TheTruth, strsize(TheTruth)) == 0)		// tell the world about it
		return 0;
	else
		return 1;

	return 0;
}

static int _gt_HelloWorldECB_AES(int test)
{
	struct AES_ctx ctx;
	char working_buffer[GKO_BLOCK_SIZE * 8 + 1];							// ECB mode wants 16 bytes * 8 = 128 + 1 for sentinel 
	uint16_t new_size;
	int ix;

	// copy the test data to a working buffer. 
	memcpy(working_buffer, TheTruth, strsize(TheTruth));				// make a copy for later test
	working_buffer[GKO_BLOCK_SIZE * 8] = 0x88;						// sentinel for sanity check
	new_size = GUTL_PadBlockRaw(working_buffer, strsize(TheTruth), 1);	// pad the data for AES
	AES_init_ctx(&ctx, aes_key);
	for (ix=0; ix < new_size; ix+=16)									// process all 16 byte blocks
		AES_ECB_encrypt(&ctx, &working_buffer[ix]);						// call AES encrypt
	AES_init_ctx(&ctx, aes_key);
	for (ix=0; ix < new_size; ix+=16)
		AES_ECB_decrypt(&ctx, &working_buffer[ix]);						// call decrypt
	assert(memcmp(working_buffer, TheTruth, strsize(TheTruth)) == 0);	// test that the decryptor output matches the original
	assert(working_buffer[GKO_BLOCK_SIZE * 8] == (char)0x88);			// just sanity checking
	if (memcmp(working_buffer, TheTruth, strsize(TheTruth)) == 0)		// tell the world about it
		return 0;
	else
		return 1;

	return 0;
}

void gt_HelloWorldAES_ECBvsGKO_ECB(int test)
{
	double AES_time, GKO_time;
	clock_t start, end;
	double cpu_time_used;
	int result, ix;
#if _DEBUG
	int loop_counter = 0xFFFF / 6;
#else
	int loop_counter = 0xFFFF * 8;
#endif

	printf("TEST%d: Gecko ECB vs AES ECB Test Setting up...\n", test);

	start = clock();
	for (ix = 0; ix < loop_counter; ix++)
		result = _gt_HelloWorldECB_AES(test);
	end = clock();
	AES_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
	if (result == 0)
	{
		printf("\nSpeed Test complete, AES took %f seconds to execute\n", cpu_time_used);
		printf("----------------\n\n");
	}
	else
	{
		printf("TEST%d: AES ECB Test Failed.\n", test);
		_getch();
	}

	start = clock();
	for (ix = 0; ix < loop_counter; ix++)
		result = _gt_HelloWorldECB_GKO(test);
	end = clock();
	GKO_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
	if (result == 0)
	{
		printf("\nSpeed Test complete, Gecko took %f seconds to execute\n", cpu_time_used);
		printf("----------------\n\n");
	}
	else
	{
		printf("TEST%d: Gecko ECB Test Failed.\n", test);
		_getch();
	}

	printf("TEST%d RESULTS: Gecko vs AES.\n", test);
	{
		printf("\nThe difference between Gecko and AES is %f%%\n", diff(GKO_time, AES_time));
		if (GKO_time < AES_time)
			printf("Gecko wins!\n");
		else
			printf("AES wins!\n");
		printf("**********************************\n\n");
	}
}

// special secret data for the ECB Sender/Receiver demonstration 
//	This is only a demonstration of ECB functionality, not how keys are shared across apps/services, etc.
//	you will likely have your own mechanism. We perform the key exchange here only to demonstrate the separation of 
//	the Sender and Receiver
#if defined(_GKO256)
const uint8_t GKO_ECB_TEST_SECRET_key[GKO_KEY_NELTS] = {	0xd2, 0xa6, 0xab, 0xf7, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 
								0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
#elif defined(_GKO192)
// we will add 8 bytes here for padding since a 24 bit key is not GKO_BLOCK_SIZE % 16
//	we will pad below
const uint8_t GKO_ECB_TEST_SECRET_key[GKO_KEY_NELTS] = {	0x2d, 0x98, 0x10, 0xa3, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
								0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }; 
#elif defined(_GKO128)
const uint8_t GKO_ECB_TEST_SECRET_key[GKO_KEY_NELTS] = { 0x60, 0x3d, 0xeb, 0x10, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif

const uint8_t GKO_ECB_TEST_SECRET_iv[GKO_IV_BUFFER_SIZE] = 
{ 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5 };

#define ECB_TEST_MAX_KEY 32		// we need to pad for 24byte keys to 32 bytes
#define ECB_TEST_SET_KEY 0
#define ECB_TEST_INIT 1
#define ECB_TEST_DATA 2
#define ECB_TEST_DONE 3

static void gt_CallHelloWorldECBReceiver(int mode, uint8_t _buff1[ECB_TEST_MAX_KEY], uint8_t _buff2[GKO_IV_BUFFER_SIZE])
{
	// static to retain state across calls
	static GKO_state_t state;
	uint16_t new_size;
	// the Sender will send us the key. No IV for ECB mode
	static uint8_t GKO_ECB_TEST_SESSION_key[GKO_KEY_NELTS];
	// ECB needs an IV. The GKO_ECB_TEST_SESSION_iv is used to store this data, that's why it needs to be static, malloc'ed, etc.
	static uint8_t GKO_ECB_TEST_SESSION_iv[GKO_IV_BUFFER_SIZE];
	uint8_t buff1[ECB_TEST_MAX_KEY];

	switch (mode)
	{
	case ECB_TEST_SET_KEY:
		if (GKO_KEY_NELTS == 24)	// special case for 192 bit keys
			memcpy(buff1, _buff1,ECB_TEST_MAX_KEY);
		else
			memcpy(buff1, _buff1,GKO_KEY_NELTS);
		// okay, now we have the encrypted the session key and session iv with the secret key that we share with the Receiver
		state.encryption_mode = GKO_mode_ecb;															// Set ECB mode
		GKO_InitState(&state, GKO_ECB_TEST_SECRET_key, NULL);	
		GKO_Decrypt(&state, buff1, GKO_KEY_NELTS == 24 ? ECB_TEST_MAX_KEY : GKO_KEY_NELTS);
		if (GKO_KEY_NELTS == 24)	
		{	// special case for 192 bit keys, unpack the 24 bytes from the 32 bytes
			new_size = GUTL_UnPadBlockRaw(buff1, ECB_TEST_MAX_KEY);
			assert(new_size == GKO_KEY_NELTS);
		}
		memcpy(GKO_ECB_TEST_SESSION_key, buff1, GKO_KEY_NELTS);
		break;
	case ECB_TEST_INIT:
		state.encryption_mode = GKO_mode_ecb;															// Set ECB mode
		GKO_InitState(&state, GKO_ECB_TEST_SESSION_key, NULL);	
		break;
	case ECB_TEST_DATA:
	{
		uint16_t cx;
		memcpy(buff1, _buff1,GKO_BLOCK_SIZE);
		// okay, wr're ready for data
		GKO_Decrypt(&state, buff1, GKO_BLOCK_SIZE);
		new_size = GUTL_UnPadBlockRaw(buff1, GKO_BLOCK_SIZE);// cleanup the buffer
		for (cx = 0; cx < new_size; cx++)					// print the output
			printf("%c", buff1[cx]);
	}
	break;
	case ECB_TEST_DONE:
		printf("\n\n");
		break;

	}
}

void gt_HelloWorldECBSender(int test)
{
	GKO_state_t state;
	uint16_t new_size;
	int ix;

	// we'll fill in the session key dynamically and share it with the Receiver
	//	We can't use GKO_KEY_NELTS here for the case when the key is 24 bytes
	//	we will need to pad it out to 32 bytes (ECB_TEST_MAX_KEY)
	static uint8_t GKO_ECB_TEST_SESSION_key[ECB_TEST_MAX_KEY];	
	uint8_t session_key_buf[ECB_TEST_MAX_KEY];
	char working_buffer[sizeof(Perrault) + 16 + 1];							// ECB mode wants GKO_BLOCK_SIZE % 16 +1 for sentinel 

	printf("TEST%d: Gecko ECB 'Send Receive' Test Setting up...\n", test);
	working_buffer[sizeof(Perrault) + 16] = 0x88;							// sentinel (sanity check)

	// now we will generate a session key for this ECB session.
	for (ix = 0; ix < GKO_KEY_NELTS; ix++)
		GKO_ECB_TEST_SESSION_key[ix] = (uint8_t)rand() % 256;

	// make a copy for our Receiver
	memcpy(session_key_buf,GKO_ECB_TEST_SESSION_key,GKO_KEY_NELTS);

	// okay, now we have the encrypted the session key and session iv with the secret key that we share with the Receiver
	state.encryption_mode = GKO_mode_ecb;															// Set ECB mode
	GKO_InitState(&state, GKO_ECB_TEST_SECRET_key, NULL);	
	// pad the data. We need this in the case of 192bit keys or 24 bytes
	//	which is not GKO_BLOCK_SIZE % 16
	new_size = GUTL_PadBlockRaw(session_key_buf, GKO_KEY_NELTS, 0);	// pad the data to 'block size'
	GKO_Encrypt(&state, session_key_buf, new_size);

	// Okay, send the session data to our Receiver
	gt_CallHelloWorldECBReceiver(ECB_TEST_SET_KEY, session_key_buf, NULL);

	// tell our Receiver to also init
	gt_CallHelloWorldECBReceiver(ECB_TEST_INIT, NULL, NULL);

	// okay! Ready to send data
	memcpy(working_buffer, Perrault, strsize(Perrault));											// make a copy for later test

	// the reciever now has the new session key and IV.
	// We will now reinit with the session data
	state.encryption_mode = GKO_mode_ecb;															// Set ECB mode
	GKO_InitState(&state, GKO_ECB_TEST_SESSION_key, NULL);	

	new_size = GUTL_PadBlockRaw(working_buffer, strsize(Perrault), 1);	// pad the data to 'block size'
	for (ix = 0; ix < new_size; ix += GKO_BLOCK_SIZE)
	{
		GKO_Encrypt(&state, &working_buffer[ix], GKO_BLOCK_SIZE);
		gt_CallHelloWorldECBReceiver(ECB_TEST_DATA, &working_buffer[ix], NULL);
	}

	// tell our Receiver we are done
	gt_CallHelloWorldECBReceiver(ECB_TEST_DONE, NULL, NULL);

	assert(working_buffer[sizeof(Perrault) + 16] == (char)0x88);			// just sanity checking

	printf("TEST%d: Gecko ECB 'Send Receive' Test complete.\n", test);
	printf("**********************************\n\n");
}



