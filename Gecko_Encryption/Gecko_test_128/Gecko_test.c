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

// turn all modes for our test harness
// You must define one of these for your implementation
//#define GKO_ENABLE_CTR									// Counter (CTR)
//#define GKO_ENABLE_ECB									// Electronic Codebook (ECB)
//#define GKO_ENABLE_PCBC									// Propagating Cipher Block Chaining (PCBC)
//#define GKO_ENABLE_CFB									// Cipher Feedback (CFB)
//#define GKO_ENABLE_OFB									// Output Feedback (OFB)

// you will also need to define one of
// I do this as a complier switch since I compile all versions here for testing
//_GKO256
//_GKO192
//_GKO128

#include "stdint.h"				// stanbdard types
#include "Gecko.h"				// main gecko include
#include "test_helpers.h"		// padding helpers
#include "Gecko_test.h"			// test functions
#include "Gecko_test_data.h"	// test data
#include "aes.h"				// AES stuff

// Mersenne Twister
void init_genrand(unsigned long s);
unsigned long genrand_int32(void);
#define RAND() ((uint8_t)genrand_int32())

// some larger storage
uint8_t big_data[4096];
uint16_t big_data_size = sizeof(big_data);
uint8_t  big_data_temp[4096];

int _tmain(int argc, _TCHAR* argv[])
{
	int done = 0;
	
	printf("\nAll test comparisons are Gecko %s vs AES %s.\n",
		(GKO_KEY_NELTS == 16 ? "128" : (GKO_KEY_NELTS == 24 ? "192" : "256")),
		(GKO_KEY_NELTS == 16 ? "128" : (GKO_KEY_NELTS == 24 ? "192" : "256")));
	printf("**********************************\n\n");

	while (!done)
	{
		printf("[0] Quit.\n");
		
		printf("[1] [CBC] Gecko Hello World! Test.\t\t\t[w] Complete regression test. Run all tests.\n");
		printf("[2] [CBC] Gecko vs AES Test.\n");
		printf("[3] [CBC] Gecko 'Send Receive' Test.\n");

		printf("[4] [CTR] Gecko Hello World! Test.\n");
		printf("[5] [CTR] Gecko vs AES Test.\n");
		printf("[6] [CTR] Gecko 'Send Receive' Test.\n");

		printf("[7] [ECB] Gecko Hello World! Test.\n");
		printf("[8] [ECB] Gecko vs AES Test.\n");
		printf("[9] [ECB] Gecko 'Send Receive' Test.\n");
#ifndef _SIZE
		printf("[a] [PCBC] Gecko Hello World! Test.\n");
		printf("[b] [PCBC] Gecko 'Send Receive' Test.\n");
		printf("[c] [CFB] Gecko Hello World! Test.\n");
		printf("[d] [CFB] Gecko 'Send Receive' Test.\n");
		printf("[e] [OFB] Gecko Hello World! Test.\n");
		printf("[f] [OFB] Gecko 'Send Receive' Test.\n");
#endif //_SIZE

		printf("[g] [CBC] Gecko vs AES SMALL BLOCK (%d bytes) Test.\n", strsize(TheTruth));
		printf("[h] [CBC] Gecko vs AES MEDIUM BLOCK (%d bytes) Test.\n", 512);
		printf("[i] [CBC] Gecko vs AES BIG BLOCK (%d bytes) Test.\n", big_data_size);

		printf("[j] [CBC] [RAW encryption] Gecko vs AES BIG BLOCK (%d bytes) Test.\n", big_data_size);

		printf("[k] [CBC] Gecko(Chain Block Cipher (CBC)) buffer Test.\n");
		printf("[l] [CBC] Gecko multi-session integrity buffer Test.\n");
		printf("[m] [CBC] Encrypted file I/O test.\n");
		printf("[n] [CBC] Encrypted file Write Example.\n");
		printf("[o] [CBC] Encrypted file Read Example.\n");

		// execute the named function
		if (_call_sample(_getch()) == 0)
			done = 1;
	}

	printf("press any key to close window\n");
	_getch();
	return 0;
}

int _call_sample(char ch)
{
	switch (ch)
	{
	case (int)'0':printf("\n");
		return 0;
	
	case (int)'1':printf("\n");
		gt_HelloWorldCBC(test(ch));
		return 1;
	case (int)'2':printf("\n");
		gt_HelloWorldAES_CBCvsGKO_CBC(test(ch));
		return 1;
	case (int)'3':printf("\n");
		gt_HelloWorldCBCSender(test(ch));
		return 1;
	
	case (int)'4':printf("\n");
		gt_HelloWorldCTR(test(ch));
		return 1;
	case (int)'5':printf("\n");
		gt_HelloWorldAES_CTRvsGKO_CTR(test(ch));
		return 1;
	case (int)'6':printf("\n");
		gt_HelloWorldCTRSender(test(ch));
		return 1;

	case (int)'7':printf("\n");
		gt_HelloWorldECB(test(ch));
		return 1;
	case (int)'8':printf("\n");
		gt_HelloWorldAES_ECBvsGKO_ECB(test(ch));
		return 1;
	case (int)'9':printf("\n");
		gt_HelloWorldECBSender(test(ch));
		return 1;

#ifndef _SIZE
	case (int)'a':printf("\n");
		gt_HelloWorldPCBC(test(ch));
		return 1;
	case (int)'b':printf("\n");
		gt_HelloWorldPCBCSender(test(ch));
		return 1;
	case (int)'c':printf("\n");
		gt_HelloWorldCFB(test(ch));
		return 1;
	case (int)'d':printf("\n");
		gt_HelloWorldCFBSender(test(ch));
		return 1;
	case (int)'e':printf("\n");
		gt_HelloWorldOFB(test(ch));
		return 1;
	case (int)'f':printf("\n");
		gt_HelloWorldOFBSender(test(ch));
		return 1;
#endif  //_SIZE

	case (int)'g':printf("\n");
		gt_gva_SmallBlockTest(test(ch), (int)strsize(TheTruth));
		return 1;
	case (int)'h':printf("\n");
		gt_gva_MediumBlockTest(test(ch), 512);
		return 1;
	case (int)'i':printf("\n");
		gt_gva_BigBlockTest(test(ch), big_data_size);
		return 1;
	case (int)'j':printf("\n");
		gt_gva_BigBlockTestRaw(test(ch), big_data_size);
		return 1;
	case (int)'k':printf("\n");
		gt_ChainBlockTest(test(ch));
		return 1;
	case (int)'l':printf("\n");
		gt_MultiSessionTest(test(ch));
		return 1;
	case (int)'m':printf("\n");
		gt_BlockModeFileTest(test(ch), (int)strsize(TheTruth));
		return 1;
	case (int)'n':printf("\n");
		gt_BlockModeWriteExample(test(ch));
		return 1;
	case (int)'o':printf("\n");
		gt_BlockModeReadExample(test(ch));
		return 1;

	case (int)'w':printf("\n");
		gt_RegressionTest();
		return 1;
	}

	return 1;
}


void gt_gva_SmallBlockTest(int test, int buff_size)
{
	GKO_state_t state;

	struct AES_ctx ctx;
	uint8_t	 temp[1024];

	printf("TEST%d: Speed Test: Gecko vs AES SMALL BLOCK (%d bytes) Test...\n", test, strsize(TheTruth));
	{
		double AES_time, GKO_time;
		uint16_t new_size;
		uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];

#if _DEBUG
		int loop_counter = 0xFFFF / 6;
#else
		int loop_counter = 0xFFFF * 8;
#endif
		{	// AES
			int kx;
			clock_t start, end;
			double cpu_time_used;
			memcpy(temp, TheTruth, buff_size);					// save the original data. We will check it later
			printf("Running AES SMALL BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
			start = clock();

			for (kx = 0; kx < loop_counter; kx++)
			{
				new_keyiv(CryptoKey, CryptoIv);
				AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);				// must call init before an encrypt/decrypt call
				new_size = GUTL_PadBlockRaw(temp, buff_size, 1);		// pad the data to 'block size', our demo uses PKCS#7
				AES_CBC_encrypt_buffer(&ctx, temp, new_size);		// call their encryptor
				AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);								// 
				AES_CBC_decrypt_buffer(&ctx, temp, new_size);		// call their decryptor
			}
			end = clock();
			AES_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
			if (memcmp(temp, TheTruth, buff_size) == 0)			// tell the world about it
			{
				printf("\nSpeed Test complete, AES took %lf seconds to execute\n", cpu_time_used);
				printf("----------------\n\n");
			}
			else
			{
				printf("TEST%d: Failed.\n", test);
				_getch();
				return;
			}
		}
		{	// GECKO
			int kx;
			clock_t start, end;
			double cpu_time_used;
			memcpy(temp, TheTruth, buff_size);					// save the original data. We will check it later
			printf("Running Gecko SMALL BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
			start = clock();

			for (kx = 0; kx < loop_counter; kx++)
			{
				new_keyiv(CryptoKey, CryptoIv);
				state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
				GKO_InitState(&state, CryptoKey, CryptoIv);											
				new_size = GUTL_PadBlockRaw(temp, buff_size, 1);
				GKO_Encrypt(&state, temp, new_size);								// call our encryptor
				state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
				GKO_InitState(&state, CryptoKey, CryptoIv);											
				GKO_Decrypt(&state, temp, new_size);								// call our decryptor
			}
			end = clock();
			GKO_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
			if (memcmp(temp, TheTruth, buff_size) == 0)								// tell the world about it
			{
				printf("\nSpeed Test complete, Gecko took %lf seconds to execute\n", cpu_time_used);
				printf("----------------\n\n");
			}
			else
			{
				printf("TEST%d: Failed.\n", test);
				_getch();
				return;
			}
		}
		printf("TEST%d RESULTS: Gecko vs AES.\n", test);
		{
			printf("\nThe difference between Gecko and AES is %lf%%\n", diff(GKO_time, AES_time));
			if (GKO_time < AES_time)
				printf("Gecko wins!\n");
			else
				printf("AES wins!\n");
			printf("**********************************\n\n");
		}

	}
}

void gt_gva_MediumBlockTest(int test, int buff_size)
{
	GKO_state_t state;
	struct AES_ctx ctx;
	double AES_time, GKO_time;
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];

	printf("TEST%d: Speed Test: Gecko vs AES MEDIUM BLOCK (%d bytes) test...\n", test, buff_size);
	{
		{
			uint16_t new_size;
#if _DEBUG
			int loop_counter = 0xFFFF / 6;
#else
			int loop_counter = 0xFFFF * 16;
#endif
			int cx; for (cx = 0; cx < buff_size; cx++)	big_data[cx] = RAND();	// fill our test buffer with random stuff
			memcpy(big_data_temp, big_data, buff_size);							// make a copy for later test
			{	// AES
				int kx;
				clock_t start, end;
				double cpu_time_used;
				printf("Running AES MEDIUM BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
				start = clock();

				for (kx = 0; kx < loop_counter; kx++)
				{
					new_keyiv(CryptoKey, CryptoIv);
					AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);						// must call init before an encrypt/decrypt call
					new_size = GUTL_PadBlockRaw(big_data_temp, buff_size, 1);		// pad the data to 'block size', our demo uses PKCS#7
					AES_CBC_encrypt_buffer(&ctx, big_data_temp, new_size);		// call their encryptor
					AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);						// 
					AES_CBC_decrypt_buffer(&ctx, big_data_temp, new_size);		// call their decryptor
				}
				end = clock();
				AES_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				if (memcmp(big_data_temp, big_data, buff_size) == 0)			// tell the world about it
				{
					printf("\nSpeed Test complete, AES took %lf seconds to execute\n", cpu_time_used);
					printf("----------------\n\n");
				}
				else
				{
					int tx;
					printf("TEST%d: Failed.\n", test);
					for (tx = 0; tx < buff_size; tx++)
					{
						if (big_data_temp[tx] != big_data[tx])
							printf("big_data_temp[%d] != big_data[%d].\n", tx, tx);
					}

					_getch();
					return;
				}
			}
			{	// GECKO
				int kx;
				clock_t start, end;
				double cpu_time_used;
				memcpy(big_data, big_data_temp, buff_size);					// put the original data back into 'data_in'
				printf("Running Gecko MEDIUM BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
				start = clock();

				for (kx = 0; kx < loop_counter; kx++)
				{
					new_keyiv(CryptoKey, CryptoIv);
					state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
					GKO_InitState(&state, CryptoKey, CryptoIv);											
					new_size = GUTL_PadBlockRaw(big_data_temp, buff_size, 1);
					GKO_Encrypt(&state, big_data_temp, new_size);				// call our encryptor
					state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
					GKO_InitState(&state, CryptoKey, CryptoIv);											
					GKO_Decrypt(&state, big_data_temp, new_size);				// call our decryptor
				}
				end = clock();
				GKO_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				if (memcmp(big_data_temp, big_data, buff_size) == 0)		// tell the world about it
				{
					printf("\nSpeed Test complete, Gecko took %lf seconds to execute\n", cpu_time_used);
					printf("----------------\n\n");
				}
				else
				{
					int tx;
					printf("TEST%d: Failed.\n", test);
					for (tx = 0; tx < buff_size; tx++)
					{
						if (big_data_temp[tx] != big_data[tx])
							printf("big_data_temp[%d] != big_data[%d].\n", tx, tx);
					}

					_getch();
					return;
				}
			}

		}
		printf("TEST%d RESULTS: Gecko vs AES.\n", test);
		{
			printf("\nThe difference between Gecko and AES is %lf%%\n", diff(GKO_time, AES_time));
			if (GKO_time < AES_time)
				printf("Gecko wins!\n");
			else
				printf("AES wins!\n");
			printf("**********************************\n\n");
		}
	}
}

void gt_gva_BigBlockTest(int test, int buff_size)
{
	GKO_state_t state;
	struct AES_ctx ctx;
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];

	// no need pa pad in this test.
	//	if you change the buff_size so that it's not a multiple of 16
	//	you will need to pad
	assert(buff_size % 16 == 0);

	printf("TEST%d: Speed Test: Gecko vs AES BIG BLOCK (%d bytes) test...\n", test, buff_size);
	{
		double AES_time, GKO_time;

		{
#if _DEBUG
			int loop_counter = 0xFFFF / 512;
#else
			int loop_counter = 0xFFFF / 2;
#endif
			int cx; for (cx = 0; cx < 4096; cx++)	big_data[cx] = RAND();	// fill our test buffer with random stuff
			memcpy(big_data_temp, big_data, buff_size);						// make a copy for later test
			{	// AES
				int kx;
				clock_t start, end;
				double cpu_time_used;
				printf("Running AES BIG BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
				start = clock();

				for (kx = 0; kx < loop_counter; kx++)
				{
					new_keyiv(CryptoKey, CryptoIv);
					AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);						// must call init before an encrypt/decrypt call
					AES_CBC_encrypt_buffer(&ctx, big_data_temp, buff_size);		// call their encryptor
					AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);						// 
					AES_CBC_decrypt_buffer(&ctx, big_data_temp, buff_size);		// call their decryptor
				}
				end = clock();
				AES_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				if (memcmp(big_data_temp, big_data, buff_size) == 0)							// tell the world about it
				{
					printf("\nSpeed Test complete, AES took %lf seconds to execute\n", cpu_time_used);
					printf("----------------\n\n");
				}
				else
				{
					int tx;
					printf("TEST%d: Failed.\n", test);
					for (tx = 0; tx < buff_size; tx++)
					{
						if (big_data_temp[tx] != big_data[tx])
							printf("big_data_temp[%d] != big_data[%d].\n", tx, tx);
					}

					_getch();
					return;
				}
			}
			{	// GECKO
				int kx;
				clock_t start, end;
				double cpu_time_used;
				memcpy(big_data, big_data_temp, buff_size);									// put the original data back into 'data_in'
				printf("Running Gecko BIG BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
				start = clock();

				for (kx = 0; kx < loop_counter; kx++)
				{
					new_keyiv(CryptoKey, CryptoIv);
					state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
					GKO_InitState(&state, CryptoKey, CryptoIv);											
					GKO_Encrypt(&state, big_data_temp, buff_size);						// call our encryptor
					state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
					GKO_InitState(&state, CryptoKey, CryptoIv);											
					GKO_Decrypt(&state, big_data_temp, buff_size);						// call our decryptor
				}
				end = clock();
				GKO_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				if (memcmp(big_data_temp, big_data, buff_size) == 0)							// tell the world about it
				{
					printf("\nSpeed Test complete, Gecko took %lf seconds to execute\n", cpu_time_used);
					printf("----------------\n\n");
				}
				else
				{
					int tx;
					printf("TEST%d: Failed.\n", test);
					for (tx = 0; tx < buff_size; tx++)
					{
						if (big_data_temp[tx] != big_data[tx])
							printf("big_data_temp[%d] != big_data[%d].\n", tx, tx);
					}

					_getch();
					return;
				}
			}

		}
		printf("TEST%d RESULTS: Gecko vs AES.\n", test);
		{
			printf("\nThe difference between Gecko and AES is %lf%%\n", diff(GKO_time, AES_time));
			if (GKO_time < AES_time)
				printf("Gecko wins!\n");
			else
				printf("AES wins!\n");
			printf("**********************************\n\n");
		}
	}
}

void gt_gva_BigBlockTestRaw(int test, int buff_size)
{
	GKO_state_t state;
	struct AES_ctx ctx;
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];

	// no need pa pad in this test.
	//	if you change the buff_size so that it's not a multiple of 16
	//	you will need to pad
	assert(buff_size % 16 == 0);

	printf("TEST%d: Speed Test: [Raw encryption] Gecko vs AES BIG BLOCK (%d bytes) test...\n", test, buff_size);
	printf("This test removes GKO/AES startup from the equation and\n");
	printf("\tpits the two against each other in raw a encryption speed test.\n");
	{
		double AES_time, GKO_time;

		{
#if _DEBUG
			int loop_counter = 0xFFFF / 512;
#else
			int loop_counter = 0xFFFF / 2;
#endif
			int cx; for (cx = 0; cx < 4096; cx++)	big_data[cx] = RAND();	// fill our test buffer with random stuff
			{	// AES
				int kx;
				clock_t start, end;
				double cpu_time_used;
				memcpy(big_data_temp, big_data, buff_size);						// make a copy
				printf("Running AES BIG BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
				new_keyiv(CryptoKey, CryptoIv);
				AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);							// outside the timing loop
				// AES encrypt
				start = clock();
				for (kx = 0; kx < loop_counter; kx++)
					AES_CBC_encrypt_buffer(&ctx, big_data_temp, buff_size);		// call their encryptor
				end = clock();
				AES_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				printf("\nSpeed Test complete, AES took %lf seconds to ENCRYPT\n", cpu_time_used);
				printf("----------------\n");
				// AES decrypt
				start = clock();
				for (kx = 0; kx < loop_counter; kx++)
					AES_CBC_decrypt_buffer(&ctx, big_data_temp, buff_size);		// call their decryptor
				end = clock();
				AES_time += cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				printf("\nSpeed Test complete, AES took %lf seconds to DECRYPT\n", cpu_time_used);
				printf("----------------\n");
			}
			{	// GECKO
				int kx;
				clock_t start, end;
				double cpu_time_used;
				memcpy(big_data_temp, big_data, buff_size);						// make a copy
				printf("Running Gecko BIG BLOCK Speed Test (0x%lX encryption/decryption passes)...\n", loop_counter);
				new_keyiv(CryptoKey, CryptoIv);
				state.encryption_mode = GKO_mode_cbc;							// outside the timing loop
				GKO_InitState(&state, CryptoKey, CryptoIv);											
				// GKO encrypt
				start = clock();
				for (kx = 0; kx < loop_counter; kx++)
					GKO_Encrypt(&state, big_data_temp, buff_size);				// call our encryptor
				end = clock();
				GKO_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				printf("\nSpeed Test complete, Gecko took %lf seconds to ENCRYPT\n", cpu_time_used);
				printf("----------------\n");
				// GKO decrypt
				start = clock();
				for (kx = 0; kx < loop_counter; kx++)
					GKO_Decrypt(&state, big_data_temp, buff_size);						// call our decryptor
				end = clock();
				GKO_time += cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
				printf("\nSpeed Test complete, Gecko took %lf seconds to DECRYPT\n", cpu_time_used);
				printf("----------------\n\n");
			}

		}
		printf("TEST%d RESULTS: Gecko vs AES.\n", test);
		{
			printf("\nThe difference between Gecko and AES is %lf%%\n", diff(GKO_time, AES_time));
			if (GKO_time < AES_time)
				printf("Gecko wins!\n");
			else
				printf("AES wins!\n");
			printf("**********************************\n\n");
		}
	}
}

void gt_ChainBlockTest(int test)
{
	GKO_state_t state;
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];

	// TEST big buffer / binary data test
	{	// gecko works on 512 byte blocks (or less if thatls all you got.)
		// Here we have a table of 128, 512 byte blocks

		static uint8_t input_buffer[128][512];
		static uint8_t test_buffer[128][512];
		int row, col;
		printf("TEST%d: Gecko(Chain Block Cipher (CBC)) buffer Test...\n", test);

		// no need to pad in this test. 
		//	if you change the block size, you may need to add padding
		assert(sizeof(input_buffer[128]) % 16 == 0);

		// lets initialize them with some data
		for (row = 0; row < 128; row++)
			for (col = 0; col < 512; col++)
				test_buffer[row][col] = input_buffer[row][col] = RAND();		// just fill with random data

		new_keyiv(CryptoKey, CryptoIv);

		// okay, now pretend each of those 512 byte columns are 512 byte file reads
		//	no need to pad
		state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(&state, CryptoKey, CryptoIv);											
		for (row = 0; row < 128; row++)
			GKO_Encrypt(&state, input_buffer[row], 512);	// encrypt each block

		state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(&state, CryptoKey, CryptoIv);											
		for (row = 0; row < 128; row++)
			GKO_Decrypt(&state, input_buffer[row], 512);	// decrypt each block

		// if all went as planned, the input_buffer should match the test_buffer
		if (memcmp(input_buffer, test_buffer, sizeof(input_buffer)) == 0)
		{
			printf("TEST%d: Gecko(Chain Block Cipher (CBC)) buffer Test PASSED\n", test);
			printf("**********************************\n\n");
		}
		else
		{
			printf("TEST%d: Failed.\n", test);
			_getch();
			return;
		}

	}
}

void gt_MultiSessionTest(int test)
{
	GKO_state_t* state1;
	GKO_state_t* state2;
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];

	// use malloc here as an alternate way - saving stack
	//	also fill with garbage
	memset(state1 = malloc(sizeof(GKO_state_t)), BFR_GARBAGE_FILL, sizeof(GKO_state_t));
	memset(state2 = malloc(sizeof(GKO_state_t)), BFR_GARBAGE_FILL, sizeof(GKO_state_t));

	// TEST mulit-session GECKO test
	{
		static uint8_t input_buffer1[128][512];
		static uint8_t test_buffer1[128][512];
		static uint8_t input_buffer2[128][512];
		static uint8_t test_buffer2[128][512];
		int row, col;

		printf("TEST%d: Gecko multi-session integrity buffer Test...\n", test);

		// no need to pad in this test.
		//	If you change the block size, you may need to pad
		assert(sizeof(input_buffer1[128]) % 16 == 0);

		// lets initialize them with some data
		for (row = 0; row < 128; row++)
		{
			for (col = 0; col < 512; col++)
			{
				test_buffer1[row][col] = input_buffer1[row][col] = RAND();		// just fill with random data
				test_buffer2[row][col] = input_buffer2[row][col] = RAND();		// just fill with different random data
			}
		}

		new_keyiv(CryptoKey, CryptoIv);

		// okay, now pretend each of those 512 byte columns are 512 byte file reads
		//	no need to pad
		state1->encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(state1, CryptoKey, CryptoIv);
		state2->encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(state2, CryptoKey, CryptoIv);

		for (row = 0; row < 128; row++)
		{
			GKO_Encrypt(state1, input_buffer1[row], 512);		// encrypt each block
			GKO_Encrypt(state2, input_buffer2[row], 512);		// encrypt each block
		}

		state1->encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(state1, CryptoKey, CryptoIv);
		state2->encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(state2, CryptoKey, CryptoIv);

		for (row = 0; row < 128; row++)
		{
			GKO_Decrypt(state1, input_buffer1[row], 512);	// decrypt each block
			GKO_Decrypt(state2, input_buffer2[row], 512);	// decrypt each block
		}

		// if all went as planned, the input_buffer should match the test_buffer
		if ((memcmp(input_buffer1, test_buffer1, sizeof(input_buffer1)) == 0) && (memcmp(input_buffer2, test_buffer2, sizeof(input_buffer2)) == 0))
		{
			printf("TEST%d: Gecko multi-session integrity buffer Test PASSED\n", test);
		}
		else
		{
			printf("TEST%d: Failed.\n", test);
		}

		printf("**********************************\n\n");
		free(state1); free(state2);
	}
}

void gt_BlockModeWriteExample(int test)
{
	GKO_state_t state;

	char buff[1024];
	FILE* fp;
	size_t bytes_written;
	uint16_t buff_size, new_size;
	char file_name[128] = { "BlockModeWriteExample" };

	printf("TEST%d: Running Block Write Example...\n", test);

	// fill buffer with data - not divisible by GKO_BLOCK_SIZE (16 bytes)
	buff_size = strsize(LoremIpsum);
	memcpy(buff, LoremIpsum, buff_size);
	MAKE_FILENAME(0);									// build a file name that incodes the the Gecko modes into the extension
	state.encryption_mode = GKO_mode_cbc;				// Set CBC mode
	GKO_InitState(&state, gko_key, gko_iv);											
	new_size = GUTL_PadBlockRaw(buff, buff_size, 1);		// pad the data to 'block size', our demo uses PKCS#7
	GKO_Encrypt(&state, buff, new_size);				// call our encryptor and get the size of the block we encrypted

	// now write the data to disk.
	fp = fopen(file_name, "wb"); assert(fp != NULL);
	bytes_written = fwrite(buff, sizeof(char), new_size, fp); assert(bytes_written == new_size);
	fclose(fp);

	printf("TEST%d: Block Mode File Write Example finished.\n", test);
	printf("Encrypted data saved %d bytes to \"%s\"\n", new_size, file_name);
	printf("**********************************\n\n");
}

void gt_BlockModeReadExample(int test)
{
	GKO_state_t state;

	char buff[1024];
	FILE* fp;
	size_t bytes_read;
	uint16_t buff_size = 1024;
	uint32_t data_size;
	char file_name[128] = { "BlockModeWriteExample" };

	printf("TEST%d: Running Block Read Example...\n", test);
	MAKE_FILENAME(GKO_mode_block);								// build a file name that incodes the the Gecko modes into the extension

	// now write the data to disk.
	fp = fopen(file_name, "rb"); assert(fp != NULL);
	bytes_read = fread(buff, sizeof(char), buff_size, fp);
	fclose(fp);

	state.encryption_mode = GKO_mode_cbc;						// Set CBC mode
	GKO_InitState(&state, gko_key, gko_iv);											
	GKO_Decrypt(&state, buff, (uint32_t)bytes_read);			// call our decryptor with only the bytes_read

	// mem clear the pad bytes and descriptor, return original data size
	data_size = GUTL_UnPadBlockRaw(buff, (uint32_t)bytes_read);

	printf("TEST%d: Block Mode File Read Example finished.\n", test);
	printf("%d bytes of encrypted data read from \"%s\", %d data bytes after removing pad and descriptor\n", bytes_read, file_name, data_size);
	printf("Text: \"%s\"\n", buff);
	printf("**********************************\n\n");
}

void gt_BlockModeFileTest(int test, int buff_size)
{
	GKO_state_t state;
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];
	uint16_t new_size;																// calculated block size after padding and adding descriptor
	FILE* fp;
	size_t bytes_written, bytes_read;
	int32_t file_size;
	uint16_t unpad_size;
	char file_name[128] = { "BlockModeFileTest" };
	uint8_t	 temp[1024];

	// TEST: Basic test of Gecko 'block mode'. 
	// Make sure what goes into encrypt() comes out of decrypt() with an 'descriptor' appended
	printf("TEST%d: Running Block Mode File Test...\n", test);
	{
		memset(temp, BFR_GARBAGE_FILL, sizeof(temp));		// set the buffer to known values so we can inspect it later
		memcpy(temp, TheTruth, buff_size);					// make a copy for later test
		MAKE_FILENAME(GKO_mode_block);						// build a file name that incodes the the Gecko modes into the extension

		new_keyiv(CryptoKey, CryptoIv);

		state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(&state, CryptoKey, CryptoIv);	
		new_size = GUTL_PadBlockRaw(temp, buff_size, 1);
		GKO_Encrypt(&state, temp, new_size);				// call our encryptor and get the size after encryption

		// now write the data to disk.
		fp = fopen(file_name, "wb"); assert(fp != NULL);
		bytes_written = fwrite(temp, sizeof(char), new_size, fp); assert(bytes_written == new_size);
		fclose(fp);

		/*
		* Okay, at this point we will assume nothing about the file we are about to open and decrypt except:
		* 1. It is block mode encrypted
		* 2. the encryption key and iv.
		* (we will however has some assert()'s with knowledge for debugging purposes.)
		*/

		memset(temp, BFR_GARBAGE_FILL, sizeof(temp));	// set the buffer to known values so we can inspect it later
		fp = fopen(file_name, "rb"); assert(fp != NULL);
		file_size = fileSize(fp);
		bytes_read = fread(temp, sizeof(char), file_size, fp);
		fclose(fp);

		// Okay, we've read the file, but we know nothing about it's padding...
		//	We will figure it out.

		state.encryption_mode = GKO_mode_cbc;								// Set CBC mode
		GKO_InitState(&state, CryptoKey, CryptoIv);	
		GKO_Decrypt(&state, temp, (uint32_t)bytes_read);					// call our decryptor with only the bytes_read

		// mem clear the pad bytes and descriptor, return original data size
		unpad_size = GUTL_UnPadBlockRaw(temp, (uint32_t)bytes_read);
		assert(unpad_size == buff_size);

		assert(memcmp(temp, TheTruth, unpad_size) == 0);					// test that the decryptor output matches the original
		if (memcmp(temp, TheTruth, unpad_size) == 0)						// tell the world about it
		{
			printf("TEST%d: Running Block Mode File Test PASSED.\n", test);
			printf("**********************************\n\n");
		}
		else
		{
			printf("TEST%d: Running Block Mode Test File Failed.\n", test);
			_getch();
			return;
		}
	}
}

void gt_RegressionTest()
{
	char exclusions[] = { '0','w','x','y','z' };
	char ch;
	for (ch = '0'; ch <= '9'; ch++)
	{
		if (memchr(exclusions, ch, sizeof(exclusions)) != NULL)
			continue;
		_call_sample(ch);
	}

	for (ch = 'a'; ch <= 'z'; ch++)
	{
		if (memchr(exclusions, ch, sizeof(exclusions)) != NULL)
			continue;
		_call_sample(ch);
	}
}

int gcd(int a, int b)
{
	int r; // remainder
	while (b > 0)
	{
		r = a % b;
		a = b;
		b = r;
	}

	return a;
}

double diff(double a, double b)
{
	double p, z;
	z = a - b;
	z = fabs(z);
	p = (a + b) / 2;
	p = (z / p) * 100;
	return p = fabs(p);
}

int test(int ch)
{
	// convert '0'-'9' to 0-9, and 'a' - 'z' to 10, etc...
	if ((char)ch >= '0' && (char)ch <= '9')
		return ch - 48;
	else return ch - 97 + 10;
}

unsigned int random_range(int range_max, int range_min)
{
	double u = (double)RAND() / (RAND_MAX + 1) * (range_max - range_min)
		+ range_min;
	return (unsigned int)u;
}

unsigned long hash(unsigned char* str)
{
	unsigned long hash = 5381;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}
int32_t fileSize(FILE* fp)
{
	int32_t sz;
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	rewind(fp);
	return sz;
}
uint32_t strsize(const char* string)
{
	return (uint32_t)strlen(string) + 1;
}

static __inline void new_keyiv(uint8_t CryptoKey[GKO_KEY_NELTS], uint8_t CryptoIv[GKO_IV_BUFFER_SIZE])
{
	int ix;
	// load up the key with random values
	for (ix = 0; ix < GKO_KEY_NELTS; ix++)
		CryptoKey[ix] = (uint8_t)RAND();

	// load up the iv with random values
	for (ix = 0; ix < GKO_IV_BUFFER_SIZE; ix++)
		CryptoIv[ix] = (uint8_t)RAND();
}