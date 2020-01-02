#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <conio.h>
#include <malloc.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <stdio.h>
#include <time.h>
#include <direct.h>
#include <assert.h> 

#include "stdint.h"
#include "Gecko.h"			// main gecko include
#include "test_helpers.h"	// padding helpers
#include "Gecko_test_data.h" 
#include "aes.h"			// AES stuff

// utils
int test(int ch);
char* dectobin(char* buff, uint32_t n);
double diff(double a, double b);
double percentYX(double y, double x);
void SetBit(uint8_t* A, size_t k);
void ClearBit(uint8_t* A, size_t k);
int TestBit(uint8_t* A, size_t k);
uint32_t CalcDiffusion(uint8_t buff1[], uint8_t buff2[], uint16_t size);

// Mersenne Twister
void init_genrand(unsigned long s);
unsigned long genrand_int32(void);
#define RAND() ((uint8_t)genrand_int32())

#define LOCAL extern

void it_ExpKeyDistribution(int test);
void it_RoundKeyDistribution(int test);
void it_ExpKeySpeedTest(int test);
void it_Stats(int test);
void it_Avalanche(int test);
void it_Confusion(int test);


int _tmain(int argc, _TCHAR* argv[])
{
	int ch, ix;
	int done=0;

	printf("\nAll test comparisons are Gecko %s vs AES %s.\n",
		(GKO_KEY_NELTS == 16 ? "128" : (GKO_KEY_NELTS == 24 ? "192" : "256")),
		(GKO_KEY_NELTS == 16 ? "128" : (GKO_KEY_NELTS == 24 ? "192" : "256")));
	printf("**********************************\n\n");

	// spin-up the rand engine
	for (ix = 0; ix < 1024 * 1024; ix++)
		RAND();

	while (!done)
	{
		printf("[0] Quit.\n");
		printf("[1] Gecko vs AES Expanded key Distribution Test.\n");
		printf("[2] Gecko vs AES Round key Distribution Test.\n");
		printf("[3] Gecko vs AES Expanded key Generation Speed Test.\n");
		printf("[4] Gecko vs AES Stats.\n");
		printf("[5] Gecko vs AES Avalanche Test.\n");
		printf("[6] Gecko vs AES Confusion Test.\n");

		switch(ch = _getch())
		{
		case (int)'0':printf("\n");
			done=1;
			break;
		case (int)'1':printf("\n");
			it_ExpKeyDistribution(test(ch));
			break;
		case (int)'2':printf("\n");
			it_RoundKeyDistribution(test(ch));
			break;
		case (int)'3':printf("\n");
			it_ExpKeySpeedTest(test(ch));
			break;
		case (int)'4':printf("\n");
			it_Stats(test(ch));
			break;
		case (int)'5':printf("\n");
			it_Avalanche(test(ch));
			break;
		case (int)'6':printf("\n");
			it_Confusion(test(ch));
			break;
		}
	}

	printf("press any key to close window\n");
	_getch();
	return 0;
}

void it_ExpKeyDistribution(int test)
{

	GKO_state_t state;
	struct AES_ctx ctx;

	int ix, jx, tx;
	double AES_duplicates, GKO_duplicates;
#ifdef _DEBUG
	const unsigned loop_count = 1024 * 8;
#else
	const unsigned loop_count = 1024 * 1024;
#endif
	uint8_t CryptoKey[GKO_KEY_NELTS];
	// setup
	AES_duplicates=0;
	GKO_duplicates=0;

	printf("TEST%d: Check expanded key distribution: Gecko vs AES\n", test);
	for(tx=0; tx < (int)loop_count; tx++)
	{
		// load up the key with random values
		for (ix=0; ix < GKO_KEY_NELTS; ix++)
			CryptoKey[ix]=(uint8_t)RAND();

		// Gecko init
		state.encryption_mode = GKO_mode_ecb;
		GKO_InitState(&state, CryptoKey, NULL);

		// get the AES 176 keys (AES_keyExpSize)
		AES_init_ctx(&ctx, CryptoKey);			

		// count all the duplicates in AES round keys
		for (ix=0; ix < AES_keyExpSize; ix++)
		{
			for (jx=ix+1; jx < AES_keyExpSize; jx++)
				if (ctx.RoundKey[ix] == ctx.RoundKey[jx])
					AES_duplicates++;
		}

		// count all the duplicates in GKO round keys
		for (ix=0; ix < AES_keyExpSize; ix++)
		{
			for (jx=ix+1; jx < AES_keyExpSize; jx++)
				if (state.expanded_keys.bytes[ix] == state.expanded_keys.bytes[jx])
					GKO_duplicates++;
		}

		continue;
	}

	// get the mean
	AES_duplicates= ((double)loop_count*AES_keyExpSize) / AES_duplicates;
	GKO_duplicates= ((double)loop_count*AES_keyExpSize) / GKO_duplicates;

	// okay, output the average results
	printf("On average, AES has %u key duplicates out of %u keys, or %0.4lf%%\n", (unsigned)AES_duplicates, AES_keyExpSize,
		(((double)AES_duplicates/(double)AES_keyExpSize) * 100.0)
		);
	printf("On average, GKO has %u key duplicates out of %u keys, or %0.4lf%%\n", (unsigned)GKO_duplicates, AES_keyExpSize,
		(((double)GKO_duplicates/(double)AES_keyExpSize) * 100.0)
		);

	printf ("%s has %0.2f%% fewer expanded key duplicates than %s\n", 
	(AES_duplicates > GKO_duplicates)  ? "GKO" : "AES",
	diff(GKO_duplicates,AES_duplicates),
	(GKO_duplicates > AES_duplicates )  ? "GKO" : "AES" 
	);
	

	printf("**********************************\n\n");
}
void it_RoundKeyDistribution(int test)
{
	extern uint8_t pumpkin_buffer[1024];
	extern uint16_t pumpkin_index;
	extern void PUMPKIN_Recorder(uint8_t mask,int mode);
	GKO_state_t state;
	struct AES_ctx ctx;
	int ix, jx, tx,mx;
	double AES_duplicates, GKO_duplicates;
	uint8_t CryptoKey[GKO_KEY_NELTS];
	uint8_t block4096[4096];
#ifdef _DEBUG
	const unsigned loop_count = 1024 * 8;
#else
	const unsigned loop_count = 1024 * 8;
#endif

	// setup
	AES_duplicates=0;
	GKO_duplicates=0;

	printf("TEST%d: Check round key distribution: Gecko vs AES\n", test);
	for(tx=0; tx < (int)loop_count; tx++)
	{
		// load up the key with random values
		for (ix=0; ix < GKO_KEY_NELTS; ix++)
			CryptoKey[ix]=(uint8_t)RAND();

		// load up the block4096 with random data
		for (ix=0; ix < 4096; ix++)
			block4096[ix]=(uint8_t)RAND();

		// AES init
		AES_init_ctx(&ctx, CryptoKey);			

		// encrypt all the blocks
		for (ix=0; ix < 4096; ix+=16)
		{
			// reset the logger
			PUMPKIN_Recorder(0,1);

			AES_ECB_encrypt(&ctx, &block4096[ix]);

			// count all the duplicates in AES round keys
			for (mx=0; mx < AES_keyExpSize; mx++)
			{
				for (jx=mx+1; jx < AES_keyExpSize; jx++)
				{
					if (pumpkin_buffer[mx] == pumpkin_buffer[jx])
					{
						assert(jx < AES_keyExpSize);
						AES_duplicates++;
					}
				}
			}
		}

		// Gecko init
		state.encryption_mode = GKO_mode_ecb;		
		GKO_InitState(&state, CryptoKey, NULL);			

		// encrypt all the blocks
		for (ix=0; ix < 4096; ix+=16)
		{
			// reset the logger
			PUMPKIN_Recorder(0,1);

			GKO_Encrypt(&state, &block4096[ix], 16);

			// count all the duplicates in GKO round keys
			for (mx=0; mx < AES_keyExpSize; mx++)
			{
				for (jx=mx+1; jx < AES_keyExpSize; jx++)
				{
					if (pumpkin_buffer[mx] == pumpkin_buffer[jx])
					{
						assert(jx < AES_keyExpSize);
						GKO_duplicates++;
					}
				}
			}
		}
	}

	// get the mean of duplicates per AES_keyExpSize keys
	AES_duplicates= ((double)loop_count*(4096/16)*AES_keyExpSize) / AES_duplicates;
	GKO_duplicates= ((double)loop_count*(4096/16)*AES_keyExpSize) / GKO_duplicates;

	// okay, output the average results
	printf("On average, AES has %u key duplicates out of %u keys, or %0.4lf%%\n", (unsigned)AES_duplicates, AES_keyExpSize,
		((double)AES_duplicates / (double)AES_keyExpSize) * 100.00
		);
	printf("On average, GKO has %u key duplicates out of %u keys, or %0.4lf%%\n", (unsigned)GKO_duplicates, AES_keyExpSize,
		((double)GKO_duplicates / (double)AES_keyExpSize) * 100.00
		);

	printf ("%s has %0.2f%% fewer round key duplicates than %s\n", 
	(AES_duplicates > GKO_duplicates)  ? "GKO" : "AES",
	diff(GKO_duplicates,AES_duplicates),
	(GKO_duplicates > AES_duplicates )  ? "GKO" : "AES" 
	);
	

	printf("**********************************\n\n");
}
void it_ExpKeySpeedTest(int test)
{
	GKO_state_t state;
	struct AES_ctx ctx;
	int ix;
	uint8_t CryptoKey[GKO_KEY_NELTS];
	double AES_time, GKO_time;
	clock_t start, end;
	double cpu_time_used;

#if _DEBUG
	int loop_counter = 0xFFFF * 10;
#else
	int loop_counter = 0xFFFF * 10;
#endif

	// load up the key with random values
	for (ix=0; ix < GKO_KEY_NELTS; ix++)
		CryptoKey[ix]=(uint8_t)RAND();

	printf("TEST%d: Check key expansion speed: Gecko vs AES\n", test);

	start = clock();
	for(ix=0; ix < (int)loop_counter; ix++)
	{
		AES_init_ctx(&ctx, CryptoKey);			
	}
	end = clock();
	AES_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
	printf("\nSpeed Test complete, AES took %f seconds to execute\n", cpu_time_used);
	printf("----------------\n\n");
	

	start = clock();
	for(ix=0; ix < (int)loop_counter; ix++)
	{
		state.encryption_mode = GKO_mode_ecb;						// Set ECB mode.  
		GKO_InitState(&state, CryptoKey, NULL);
	}
	end = clock();
	GKO_time = cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
	printf("\nSpeed Test complete, Gecko took %f seconds to execute\n", cpu_time_used);
	printf("----------------\n\n");

	printf("TEST%d RESULTS: Gecko vs AES.\n", test);

	printf("\nThe difference between Gecko and AES is %lf%%\n", diff(GKO_time, AES_time));
	if (GKO_time < AES_time)
		printf("Gecko wins!\n");
	else
		printf("AES wins!\n");
		
	printf("**********************************\n\n");
}
void it_Stats(int test)
{	// As of 12/14/2019
	double AES_size=4.46; // KB (4,577 bytes) 
	double GKO_size=4.14; // KB (4,240 bytes)
	uint8_t location[] = "Gecko_Individual_Modes/AES_vs_GKO_Size/Size";
	uint8_t* name;
	printf("TEST%d: Object code size in CBC mode: Gecko vs AES\n", test);

	printf("\tAES obj size: %2.2lf KB\n", AES_size);
	printf("\tGecko obj size: %2.2lf KB\n", GKO_size);

	if (GKO_size > AES_size)
		name = "aes.obj";
	else
		name="gecko.obj";
	
	printf("\t%s/%s is %2.2f%% smaller\n", location, name, diff(GKO_size, AES_size));

	printf("**********************************\n\n");
}
void it_Avalanche(int test)
{
#if _DEBUG
	const int loop_count = 10 * 10;
#else
	const int loop_count = 1024 * 10;
#endif
	
	/*	Diffusion 
	*	Diffusion means that the output bits should depend on the input bits in a very complex way. 
	*	In a cipher with good diffusion, if one bit of the plaintext is changed, then the ciphertext should change completely, in an unpredictable or pseudorandom manner. 
	*	In particular, for a randomly chosen input, if one flips the i-th bit, 
	*		then the probability that the j-th output bit will change should be one half, for any i and j — this is termed the strict avalanche criterion. 
	*	More generally, one may require that flipping a fixed set of bits should change each output bit with probability one half.
	*/
	void AvalancheCBC(int test, const int loop_count);
	void AvalancheECB(int test, const int loop_count);
	AvalancheCBC(test, loop_count);
	AvalancheECB(test, loop_count*100);
}

void AvalancheECB(int test, const int loop_count)
{
	GKO_state_t state;
	struct AES_ctx ctx;

	uint8_t hello[] = { 'H','e','l','l','o',' ','W','o','r','l','d','!','\0',0x03,0x03,0x03 };
	char changed_bit[16];	// <== change one bit
	uint8_t buff1[GKO_BLOCK_SIZE], buff2[GKO_BLOCK_SIZE], buff3[GKO_BLOCK_SIZE], buff4[GKO_BLOCK_SIZE];
	uint8_t CryptoKey[GKO_KEY_NELTS];
	int ix, jx;
	uint32_t gko_count = 0, aes_count = 0, bit;

	printf("TEST%d: Avalanche/Diffusion test: Gecko vs AES ECB\n", test);

	for (jx = 0; jx < loop_count; jx++)
	{
		// load up the key with random values
		for (ix = 0; ix < GKO_KEY_NELTS; ix++)
			CryptoKey[ix] = (uint8_t)RAND();

		memcpy(changed_bit, hello, sizeof(hello));
		bit = CryptoKey[0] % (sizeof(hello) * 8);
		(TestBit(changed_bit, bit)) ? ClearBit(changed_bit, bit) :	// flip 1 bit in the CryptoKey
			SetBit(changed_bit, bit);

		memcpy(buff1, hello, sizeof(hello));						// make a copy for later test
		state.encryption_mode = GKO_mode_ecb;						// Set ECB mode.  
		GKO_InitState(&state, CryptoKey, NULL);
		GKO_Encrypt(&state, buff1, GKO_BLOCK_SIZE);					// call our encryptor

		memcpy(buff2, changed_bit, sizeof(changed_bit));						// make a copy for later test
		state.encryption_mode = GKO_mode_ecb;						// Set ECB mode.  
		GKO_InitState(&state, CryptoKey, NULL);
		GKO_Encrypt(&state, buff2, GKO_BLOCK_SIZE);					// call our encryptor

		gko_count += CalcDiffusion(buff1, buff2, GKO_BLOCK_SIZE);

		memcpy(buff3, hello, sizeof(hello));						// make a copy for later test
		AES_init_ctx(&ctx, CryptoKey);
		AES_ECB_encrypt(&ctx, buff3);

		memcpy(buff4, changed_bit, sizeof(changed_bit));						// make a copy for later test
		AES_init_ctx(&ctx, CryptoKey);
		AES_ECB_encrypt(&ctx, buff4);

		aes_count += CalcDiffusion(buff3, buff4, GKO_BLOCK_SIZE);
	}

	printf("GKO results in %.3lf%% diffusion: %u changed of %d bits\n", percentYX(gko_count, GKO_BLOCK_SIZE * 8 * loop_count), gko_count, GKO_BLOCK_SIZE * 8 * loop_count);
	printf("AES results in %.3lf%% diffusion: %u changed of %d bits\n", percentYX(aes_count, GKO_BLOCK_SIZE * 8 * loop_count), aes_count, GKO_BLOCK_SIZE * 8 * loop_count);

	printf("TEST%d RESULTS: Gecko vs AES ECB.\n", test);
	{
		printf("\nThe difference between Gecko and AES is %lf%%\n", diff(gko_count, aes_count));
		if (aes_count < gko_count)
			printf("Gecko wins!\n");
		else
			printf("AES wins!\n");
	}

	printf("**********************************\n\n");
}
void AvalancheCBC(int test, const int loop_count)
{
	GKO_state_t state;
	struct AES_ctx ctx;
	uint8_t original_text[sizeof(Perrault) + 16];		// original text. 
	uint8_t text_one_bit_diff[sizeof(Perrault) + 16];	// <== change one bit
	static uint8_t buff1[sizeof(Perrault) + 16],buff2[sizeof(Perrault) + 16],buff3[sizeof(Perrault) + 16],buff4[sizeof(Perrault) + 16];
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE];
	int ix, jx;
	uint32_t gko_count=0, aes_count=0, bit;
	uint16_t new_size;

	printf("TEST%d: Avalanche/Diffusion test: Gecko vs AES CBC\n", test);

	for (jx=0; jx < loop_count; jx++)
	{
		// load up the key with random values
		for (ix = 0; ix < GKO_KEY_NELTS; ix++)
			CryptoKey[ix] = (uint8_t)RAND();

		// load up the iv with random values
		for (ix = 0; ix < GKO_IV_BUFFER_SIZE; ix++)
			CryptoIv[ix] = (uint8_t)RAND();

		// first pad the text original_text out to a multiple of block size
		memcpy(original_text, Perrault, sizeof(Perrault));
		new_size = GUTL_PadBlockRaw(original_text, sizeof(Perrault), 1);
		// now flip one bit in a copy of the text
		memcpy(text_one_bit_diff, original_text, new_size);
		bit = CryptoKey[0] % (new_size * 8);
		(TestBit(text_one_bit_diff, bit)) ? ClearBit(text_one_bit_diff, bit) : 
			SetBit(text_one_bit_diff, bit);

		memcpy(buff1, original_text, new_size);						// make a copy for later test
		state.encryption_mode = GKO_mode_cbc;						// Set CBC mode.  
		GKO_InitState(&state, CryptoKey, CryptoIv);
		GKO_Encrypt(&state, buff1, new_size);					// call our encryptor

		memcpy(buff2, text_one_bit_diff, new_size);						// make a copy for later test
		state.encryption_mode = GKO_mode_cbc;						// Set CBC mode.  
		GKO_InitState(&state, CryptoKey, CryptoIv);
		GKO_Encrypt(&state, buff2, new_size);					// call our encryptor

		gko_count += CalcDiffusion(buff1, buff2, new_size);

		memcpy(buff3, original_text, new_size);						// make a copy for later test
		AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);
		AES_CBC_encrypt_buffer(&ctx, buff3, new_size);

		memcpy(buff4, text_one_bit_diff, new_size);						// make a copy for later test
		AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);
		AES_CBC_encrypt_buffer(&ctx, buff4,new_size);

		aes_count += CalcDiffusion(buff3, buff4, new_size);
	}

	printf("GKO results in %.3lf%% diffusion: %u changed of %d bits\n", percentYX(gko_count, new_size * 8 * loop_count), gko_count, new_size * 8 * loop_count);
	printf("AES results in %.3lf%% diffusion: %u changed of %d bits\n", percentYX(aes_count, new_size * 8 * loop_count), aes_count, new_size * 8 * loop_count);

	printf("TEST%d RESULTS: Gecko vs AES CBC.\n", test);
	{
		printf("\nThe difference between Gecko and AES is %lf%%\n", diff(gko_count, aes_count));
		if (aes_count < gko_count)
			printf("Gecko wins!\n");
		else
			printf("AES wins!\n");
	}

	printf("**********************************\n\n");
}
void it_Confusion(int test)
{
#if _DEBUG
	const int loop_count = 100 * 10;
#else
	const int loop_count = 1024 * 10;
#endif

	/*	Confusion
	*	One aim of confusion is to make it very hard to find the key even if one has a large number of plaintext-ciphertext pairs produced with the same key. 
	*	Therefore, each bit of the ciphertext should depend on the entire key, and in different ways on different bits of the key. 
	*	In particular, changing one bit of the key should change the ciphertext completely.
	*/
	void ConfusionCBC(int test, const int loop_count);
	void ConfusionECB(int test, const int loop_count);
	ConfusionCBC(test, loop_count);
	ConfusionECB(test, loop_count*100);
}
void ConfusionECB(int test, const int loop_count)
{
	GKO_state_t state;
	struct AES_ctx ctx;

	uint8_t hello[] = { 'H','e','l','l','o',' ','W','o','r','l','d','!','\0',0x03,0x03,0x03 };
	uint8_t buff1[GKO_BLOCK_SIZE], buff2[GKO_BLOCK_SIZE], buff3[GKO_BLOCK_SIZE], buff4[GKO_BLOCK_SIZE];
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoKeyCopy[GKO_KEY_NELTS];
	int ix, jx;
	uint32_t gko_count = 0, aes_count = 0, bit;

	printf("TEST%d: Confusion test: Gecko vs AES ECB\n", test);

	for (jx = 0; jx < loop_count; jx++)
	{
		// load up the key with random values
		for (ix = 0; ix < GKO_KEY_NELTS; ix++)
			CryptoKey[ix] = (uint8_t)RAND();

		memcpy(CryptoKeyCopy, CryptoKey, sizeof(CryptoKey));		// make a modifiable copy of our crypto key
		bit = CryptoKey[0] % (GKO_BLOCK_SIZE * 8);					// flip 1 bit in the CryptoKey
		(TestBit(CryptoKeyCopy, bit)) ? ClearBit(CryptoKeyCopy, bit) :
			SetBit(CryptoKeyCopy, bit);

		// first, get the ciphertext from this key
		memcpy(buff1, hello, sizeof(hello));						// make a copy for later test
		state.encryption_mode = GKO_mode_ecb;						// Set ECB mode.  
		GKO_InitState(&state, CryptoKey, NULL);
		GKO_Encrypt(&state, buff1, GKO_BLOCK_SIZE);					// call our encryptor

		// get the ciphertext again, but with one bit flipped in the key
		memcpy(buff2, hello, sizeof(hello));						// make a copy for later test
		state.encryption_mode = GKO_mode_ecb;						// Set ECB mode.  
		GKO_InitState(&state, CryptoKeyCopy, NULL);					// one bit changed
		GKO_Encrypt(&state, buff2, GKO_BLOCK_SIZE);					// call our encryptor

		gko_count += CalcDiffusion(buff1, buff2, GKO_BLOCK_SIZE);

		// now do the same for AES
		memcpy(buff3, hello, sizeof(hello));						// make a copy for later test
		AES_init_ctx(&ctx, CryptoKey);
		AES_ECB_encrypt(&ctx, buff3);

		memcpy(buff4, hello, sizeof(hello));						// make a copy for later test
		AES_init_ctx(&ctx, CryptoKeyCopy);							// one bit changed
		AES_ECB_encrypt(&ctx, buff4);

		aes_count += CalcDiffusion(buff3, buff4, GKO_BLOCK_SIZE);
	}

	printf("GKO results in %.3lf%% confusion: %u changed of %d bits\n", percentYX(gko_count, GKO_BLOCK_SIZE * 8 * loop_count), gko_count, GKO_BLOCK_SIZE * 8 * loop_count);
	printf("AES results in %.3lf%% confusion: %u changed of %d bits\n", percentYX(aes_count, GKO_BLOCK_SIZE * 8 * loop_count), aes_count, GKO_BLOCK_SIZE * 8 * loop_count);

	printf("TEST%d RESULTS: Gecko vs AES ECB.\n", test);
	{
		printf("\nThe difference between Gecko and AES is %lf%%\n", diff(gko_count, aes_count));
		if (aes_count < gko_count)
			printf("Gecko wins!\n");
		else
			printf("AES wins!\n");
	}

	printf("**********************************\n\n");
}
void ConfusionCBC(int test, const int loop_count)
{
	GKO_state_t state;
	struct AES_ctx ctx;
	uint8_t original_text[sizeof(Perrault) + 16];		// original text. 
	static uint8_t buff1[sizeof(Perrault) + 16], buff2[sizeof(Perrault) + 16], buff3[sizeof(Perrault) + 16], buff4[sizeof(Perrault) + 16];
	uint8_t CryptoKey[GKO_KEY_NELTS], CryptoIv[GKO_IV_BUFFER_SIZE], CryptoKeyCopy[GKO_KEY_NELTS];
	int ix, jx;
	uint32_t gko_count = 0, aes_count = 0, bit;
	uint16_t new_size;

	printf("TEST%d: Confusion test: Gecko vs AES CBC\n", test);
	// first pad the text original_text out to a multiple of block size
	memcpy(original_text, Perrault, sizeof(Perrault));
	new_size = GUTL_PadBlockRaw(original_text, sizeof(Perrault), 1);

	for (jx = 0; jx < loop_count; jx++)
	{
		// load up the key with random values
		for (ix = 0; ix < GKO_KEY_NELTS; ix++)
			CryptoKey[ix] = (uint8_t)RAND();

		// load up the iv with random values
		for (ix = 0; ix < GKO_IV_BUFFER_SIZE; ix++)
			CryptoIv[ix] = (uint8_t)RAND();

		memcpy(CryptoKeyCopy, CryptoKey, sizeof(CryptoKey));		// make a modifiable copy of our crypto key
		bit = CryptoKey[0] % (GKO_BLOCK_SIZE * 8);						// flip 1 bit in the CryptoKey
		(TestBit(CryptoKeyCopy, bit)) ? ClearBit(CryptoKeyCopy, bit) :
			SetBit(CryptoKeyCopy, bit);

		memcpy(buff1, original_text, new_size);						// make a copy for later test
		state.encryption_mode = GKO_mode_cbc;						// Set CBC mode.  
		GKO_InitState(&state, CryptoKey, CryptoIv);
		GKO_Encrypt(&state, buff1, new_size);					// call our encryptor

		memcpy(buff2, original_text, new_size);						// make a copy for later test
		state.encryption_mode = GKO_mode_cbc;						// Set CBC mode.  
		GKO_InitState(&state, CryptoKeyCopy, CryptoIv);			// one bit changed
		GKO_Encrypt(&state, buff2, new_size);					// call our encryptor

		gko_count += CalcDiffusion(buff1, buff2, new_size);

		memcpy(buff3, original_text, new_size);						// make a copy for later test
		AES_init_ctx_iv(&ctx, CryptoKey, CryptoIv);
		AES_CBC_encrypt_buffer(&ctx, buff3, new_size);

		memcpy(buff4, original_text, new_size);						// make a copy for later test
		AES_init_ctx_iv(&ctx, CryptoKeyCopy, CryptoIv);				// one bit changed
		AES_CBC_encrypt_buffer(&ctx, buff4, new_size);

		aes_count += CalcDiffusion(buff3, buff4, new_size);
	}

	printf("GKO results in %.3lf%% confusion: %u changed of %d bits\n", percentYX(gko_count, new_size * 8 * loop_count), gko_count, new_size * 8 * loop_count);
	printf("AES results in %.3lf%% confusion: %u changed of %d bits\n", percentYX(aes_count, new_size * 8 * loop_count), aes_count, new_size * 8 * loop_count);

	printf("TEST%d RESULTS: Gecko vs AES CBC.\n", test);
	{
		printf("\nThe difference between Gecko and AES is %lf%%\n", diff(gko_count, aes_count));
		if (aes_count < gko_count)
			printf("Gecko wins!\n");
		else
			printf("AES wins!\n");
	}

	printf("**********************************\n\n");
}


int test(int ch)
{
	// convert '0'-'9' to 0-9, and 'a' - 'z' to 10, etc...
	if ((char)ch >= '0' && (char)ch <= '9')
		return ch - 48;
	else return ch -97 + 10;
}
char* dectobin(char* buff, uint32_t n)
{
	uint32_t k, ix=0;
	int32_t c; 
	for (c = 31; c >= 0; c--)
	{
		k = n >> c;

		if (k & 1)
			buff[ix++] = '1'; // printf("1");
		else
			buff[ix++] = '0'; // printf("0");
	}

	buff[ix] = '\0'; // terminate string
	return buff;
}

double diff(double a, double b)
{
	double p,z;
	z=a-b;
	z=fabs(z);
	p=(a+b)/2;
	p=(z/p)*100;
	return p=fabs(p);   
}
double percentYX(double y, double x)
{
	double p = y / x;
	return p * 100.0;
}

uint8_t pumpkin_buffer[1024];
uint16_t pumpkin_index;
extern void PUMPKIN_Recorder(uint8_t mask,int mode)
{
	if (mode == 1)
	{
		memset (pumpkin_buffer,0,sizeof(pumpkin_buffer));
		pumpkin_index=0;
		return;
	}

	if (pumpkin_index < sizeof(pumpkin_buffer))
	{
		pumpkin_buffer[pumpkin_index++] = mask;
	}
	else
		printf("");
	
	return;
}
uint32_t CalcDiffusion(uint8_t buff1[], uint8_t buff2[], uint16_t size)
{
	int ix;
	uint32_t count = 0;
	for (ix = 0; ix < size * 8; ix++)
	{
		if (TestBit(buff1, ix) != TestBit(buff2, ix))
			count++;
	}

	return count;
}
void SetBit(uint8_t* A, size_t k)
{
	(A[(k / (sizeof(A[0]) * 8))] |= (1 << (k % (sizeof(A[0]) * 8))));
}
void ClearBit(uint8_t* A, size_t k)
{
	// Clearing the kth bit in array A
	(A[(k / (sizeof(A[0]) * 8))] &= ~(1 << (k % (sizeof(A[0]) * 8))));
}
int TestBit(uint8_t* A, size_t k)
{
	// TestBit(A, k): test the kth bit in the bit array A:
	return	(A[(k / (sizeof(A[0]) * 8))] & (1 << (k % (sizeof(A[0]) * 8))));
}