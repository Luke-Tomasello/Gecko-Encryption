/*
   A C-implementation of the Gecko (GKO) Cryptographic Library
   Designed and Coded by Luke Tomasello.

   Copyright (C) 2019 - Present, Luke Tomasello,
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

	 1. Redistributions of source code must retain the above copyright
		notice, this list of conditions and the following disclaimer.

	 2. Redistributions in binary form must reproduce the above copyright
		notice, this list of conditions and the following disclaimer in the
		documentation and/or other materials provided with the distribution.

	 3. The names of its contributors may not be used to endorse or promote
		products derived from this software without specific prior written
		permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


   Feedback is welcome.
   Facebook: https://www.facebook.com/Tomasello.Software
   email: luke@tomasello.com
*/

#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <malloc.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <stdio.h>
#include <time.h>
#include <direct.h>
#include <assert.h> 
// Gecko stuff
#include "stdint.h"
#include "Gecko.h" 

// When building the gecko_test_internal program, you need to define _GECKO_TEST_INTERNAL
//	so that gecko_test_internal can get access to these otherwise static functions.
#if defined(_DEBUG) || defined(_GECKO_TEST_INTERNAL) 
#define LOCAL extern
#elif defined(_SIZE)
#define LOCAL static
#else
#define LOCAL static __inline
#endif

// defining SPEED_OVER_SIZE unrolls all the 16 byte loops
//	that processes input bytes resulting in ~100% speedups
#ifndef _SIZE
#define GKO_SPEED_OVER_SIZE
#endif

#ifdef GKO_ENABLE_CBC
LOCAL void GKO_EncryptCBC(GKO_state_t* state, uint8_t* bp);
LOCAL void GKO_DecryptCBC(GKO_state_t* state, uint8_t* bp);
#endif // GKO_ENABLE_CBC
#ifdef GKO_ENABLE_CTR	
LOCAL void GKO_EncryptCTR(GKO_state_t* state, uint8_t* bp);
LOCAL void GKO_DecryptCTR(GKO_state_t* state, uint8_t* bp);
#endif // GKO_ENABLE_CTR	
#ifdef GKO_ENABLE_ECB
LOCAL void GKO_EncryptECB(GKO_state_t* state, uint8_t* bp);
LOCAL void GKO_DecryptECB(GKO_state_t* state, uint8_t* bp);
#endif // GKO_ENABLE_ECB
#ifdef GKO_ENABLE_PCBC
LOCAL void GKO_EncryptPCBC(GKO_state_t* state, uint8_t* bp);
LOCAL void GKO_DecryptPCBC(GKO_state_t* state, uint8_t* bp);
#endif // GKO_ENABLE_PCBC
#ifdef GKO_ENABLE_CFB
LOCAL void GKO_EncryptCFB(GKO_state_t* state, uint8_t* bp);
LOCAL void GKO_DecryptCFB(GKO_state_t* state, uint8_t* bp);
#endif // GKO_ENABLE_CFB
#ifdef GKO_ENABLE_OFB
LOCAL void GKO_EncryptOFB(GKO_state_t* state, uint8_t* bp);
LOCAL void GKO_DecryptOFB(GKO_state_t* state, uint8_t* bp);
#endif // GKO_ENABLE_OFB

LOCAL void GKO_ExpandKeys(GKO_state_t* state, const uint8_t key[]);
LOCAL void GKO_Cipher(GKO_state_t* state, uint8_t* bp, GKO_Cipher_Direction_t direction);
LOCAL void GKO_ShuffleBits(uint8_t buff[]);
LOCAL void GKO_InvShuffleBits(uint8_t buff[]);
LOCAL void GKO_ShuffleBytes(const uint8_t exchanges[], uint8_t buff[]);
LOCAL void GKO_InvShuffleBytes(const uint8_t exchanges[], uint8_t buff[]);
LOCAL void GKO_SubBytes(uint8_t buff[]);
LOCAL void GKO_InvSubBytes(uint8_t buff[]);
LOCAL void GKO_SboxMaskBytes(const uint8_t round_key[], uint8_t bp[]);
LOCAL void KeyedShuffle(const uint8_t table[], uint8_t key[], const uint32_t size);
LOCAL void GKO_CipherMaskBytes(const uint8_t round_key[], uint8_t* bp);
LOCAL void GKO_XORBytes(const uint8_t exchanges[], uint8_t buff[]);
LOCAL void GKO_InvXORBytes(const uint8_t exchanges[], uint8_t buff[]);
static const uint8_t gko_sbox[256];		// forward declaration
static const uint8_t gko_rsbox[256];	// forward declaration

#ifdef GKO_ENABLE_CTR
LOCAL uint8_t* GKO_GetIVp(GKO_state_t* state)
{	
	if (state->iv_buffer.next_ele == GKO_BLOCK_SIZE)
		state->iv_buffer.next_ele=0;

	return &state->iv_buffer.bytes[state->iv_buffer.next_ele++];
}
LOCAL uint8_t* GKO_IncIv(GKO_state_t* state)
{
	uint8_t* cp;

	// if the previous byte was 255, set to 0
	if (*(cp = GKO_GetIVp(state)) == 255)
	{	// this IS the increment
		*cp = 0;	
		return state->iv_buffer.bytes;
	}

	// increment
	(*cp)++;
	return state->iv_buffer.bytes;
}
#endif // GKO_ENABLE_CTR 

#if defined (GKO_ENABLE_CBC) || defined (GKO_ENABLE_OFB) || defined (GKO_ENABLE_PCBC) || defined (GKO_ENABLE_CTR) || defined (GKO_ENABLE_CFB)
LOCAL void GKO_SetCB(GKO_state_t* state, const uint8_t* buff)
{	//	last-block encrypted data is placed here and used for encrypting/decrypting the next block.
	memcpy(state->chaining_buffer.bytes, buff, GKO_BLOCK_SIZE);
}
#endif // GKO_ENABLE_CBC etc.
#if defined (GKO_ENABLE_CTR) || defined (GKO_ENABLE_OFB) || defined (GKO_ENABLE_CTR) || defined (GKO_ENABLE_CFB)
LOCAL uint8_t* GKO_GetCB(GKO_state_t* state)
{
	return state->chaining_buffer.bytes;
}
#endif // GKO_ENABLE_CTR etc.
#if defined (GKO_ENABLE_CBC) || defined (GKO_ENABLE_CBC) || defined (GKO_ENABLE_OFB) || defined(GKO_ENABLE_CTR) || defined (GKO_ENABLE_PCBC) || defined (GKO_ENABLE_CFB)
LOCAL void GKO_XorWithCB(GKO_state_t* state, uint8_t* buff)
{	uint32_t ix;
	//	XOR contents passed in buff with chaining_buffer 
	for (ix=0; ix < GKO_BLOCK_SIZE; ix++)
		buff[ix] ^= state->chaining_buffer.bytes[ix];
}
#endif // GKO_ENABLE_CBC  etc.
#if defined (GKO_ENABLE_PCBC)
LOCAL void GKO_XorToCB(GKO_state_t* state, uint8_t* buff)
{	// XOR what's in the chaining buffer with what's in buff
	int ix;
	for (ix = 0; ix < GKO_BLOCK_SIZE; ix++)
		state->chaining_buffer.bytes[ix] ^= buff[ix];
}
#endif // GKO_ENABLE_PCBC
#ifndef _GECKO_TEST_INTERNAL
// INSTRUMENTATION:
//	the Gecko pumpkin recorder simply tracks 'masks used' by a given cipher
//	these values are then processed within Gecko_test_internal to calc duplicate keys
#define PUMPKIN_Recorder(x,y); 
#else
extern void PUMPKIN_Recorder(uint8_t,int);
#endif
#ifdef GKO_ENABLE_CBC
LOCAL void GKO_EncryptCBC(GKO_state_t* state, uint8_t* bp)
{    /* CBC Mode:  Encryption                  Encryption                Decryption
     * 
     *              [plaintext]                  [plaintext]                [ciphertext]                [ciphertext]
     *                  |                               |                         |                           |
     *                  |            +---------------->XOR                        +----------+                +---...
     *                  |            |                  |                         |          |                |
     *    [IV]=>       XOR           |                  |                         V          |                V
     *                  |            |                  |            [key]=>[block cipher]   |   [key]=>[block cipher]
     *                  V            |                  V                         |          |                |
     *    [key]=>    [block cipher]  |    [key]=> [block cipher]        [IV]=>   XOR         +-------------> XOR
     *                  |            |                  |                         |                           |         
     *                  +------------+                  |                         V                           V
     *                  |                               |                    [plaintext]                 [plaintext]
     *                  V                               V
     *             [ciphertext]                    [ciphertext]
     */
	GKO_XorWithCB(state, bp);					// initially, this is set to IV
	GKO_Cipher(state, bp, GKO_cipher_forward);	// encrypt
	GKO_SetCB(state, bp);						// store ciphertext in chaining buffer
}
LOCAL void GKO_DecryptCBC(GKO_state_t* state, uint8_t* bp)
{	
	uint8_t ciphertext[GKO_BLOCK_SIZE];			// ciphertext storage
	memcpy(ciphertext, bp, GKO_BLOCK_SIZE);		// backup ciphertext
	GKO_Cipher(state, bp,GKO_cipher_backward);	// decrypt the buffer	
	GKO_XorWithCB(state, bp);					// XOR the ciphertext chaining buffer
	GKO_SetCB(state, ciphertext);				// store ciphertext in chaining buffer
}
#endif // GKO_ENABLE_CBC
#ifdef GKO_ENABLE_CTR	
LOCAL void GKO_EncryptCTR(GKO_state_t* state, uint8_t* bp)
{	/* CTR Mode:   Encryption                 Decryption
     *
     *            nonce    counter++              nonce    counter++
     *              [NNNNNNNC]                      [NNNNNNNC] 
     *                  |                               |
     *                  V                               V
     *    [key]=> [block cipher]         [key]=>  [block cipher]
     *                  |                               |
     *                  |                               |
     *    [plaintext]=>XOR               [ciphertext]=>XOR
     *                  |                               |
     *                  V                               V
     *             [ciphertext]                    [plaintext]
     */
	GKO_Cipher(state, GKO_GetCB(state),GKO_cipher_symmetrical);	// encrypt IV
	GKO_XorWithCB(state, bp);									// XOR plaintext with chaining buffer (initially set to IV)
	GKO_SetCB(state,GKO_IncIv(state));							// store incremented IV in chaining buffer
}
LOCAL void GKO_DecryptCTR(GKO_state_t* state, uint8_t* bp)
{
	// symmetric encryption
	GKO_EncryptCTR(state, bp);
}
#endif // GKO_ENABLE_CTR	
#ifdef GKO_ENABLE_ECB
LOCAL void GKO_EncryptECB(GKO_state_t* state, uint8_t* bp)
{	/* ECB Mode:   Encryption                Decryption
     * 
     *             [plaintext]                 [ciphertext] 
     *                  |                           |
     *                  V                           V
     *    [key]=> [block cipher]      [key]=> [block cipher]
     *                  |                           |
     *                  V                           V
     *             [ciphertext]                [plaintext]
     */
	GKO_Cipher(state, bp, GKO_cipher_forward);	// encrypt the plaintext
	return;
}
LOCAL void GKO_DecryptECB(GKO_state_t* state, uint8_t* bp)
{
	// symmetric encryption
	GKO_Cipher(state, bp, GKO_cipher_backward);
}
#endif // GKO_ENABLE_ECB
#ifdef GKO_ENABLE_PCBC
LOCAL void GKO_EncryptPCBC(GKO_state_t* state, uint8_t* bp)
{    /* PCBC Mode:  Encryption                  Encryption                Decryption
     * 
     *              [plaintext]                 [plaintext]               [ciphertext]                 [ciphertext]
     *                  |                            +--...                    |                            |
     *                  +--------XOR--------------->XOR                        +----------+                 +---...
     *                  |         |                  |                         |          |                 |
     *    [IV]=>       XOR        |                  |                         V          |                 V
     *                  |         |                  |            [key]=>[block cipher]   |    [key]=>[block cipher]
     *                  V         |                  V                         |          |                 |
     *    [key]=> [block cipher]  |    [key]=> [block cipher]        [IV]=>   XOR        XOR-------------> XOR
     *                  |         |                  |                         |          |                 |         
     *                  +---------+                  +--...                    V          |                 V
     *                  |                            |                    [plaintext]-----|            [plaintext]-...
     *                  V                            V
     *             [ciphertext]                  [ciphertext]
     */
	uint8_t plaintext[GKO_BLOCK_SIZE];			// make a copy of the plaintext
	memcpy(plaintext,bp,GKO_BLOCK_SIZE);
	GKO_XorWithCB(state, bp);					// XOR plaintext with chaining buffer (initially set to IV)
	GKO_Cipher(state, bp, GKO_cipher_forward);	// encrypt
	GKO_SetCB(state, bp);						// store ciphertext in chaining buffer
	GKO_XorToCB(state, plaintext);				// XOR the chaining buffer with the plaintext (PCBC)
}
LOCAL void GKO_DecryptPCBC(GKO_state_t* state, uint8_t* bp)
{	
	uint8_t ciphertext[GKO_BLOCK_SIZE];			// ciphertext storage
	memcpy(ciphertext, bp, GKO_BLOCK_SIZE);		// backup ciphertext
	GKO_Cipher(state, bp,GKO_cipher_backward);	// decrypt the buffer	
	GKO_XorWithCB(state, bp);					// XOR ciphertext with chaining buffer (initially set to IV)
	GKO_SetCB(state, ciphertext);				// store ciphertext in chaining buffer
	GKO_XorToCB(state, bp);						// XOR the chaining buffer with the plaintext (PCBC)
}
#endif // GKO_ENABLE_PCBC
#ifdef GKO_ENABLE_CFB
LOCAL void GKO_EncryptCFB(GKO_state_t* state, uint8_t* bp)
{    /* CFB Mode:  Encryption                  Encryption                Decryption
     * 
     *                [IV]                                                     [IV]                                  
     *                  |                                                        |                              
     *                  |         +-------------------+                          |           +-----------------+            . 
     *                  |         |                   |                          |           |                 |            .
     *                  |         |                   |                          V           |                 V            .
     *                  |         |                   |            [key]=> [block cipher]    |    [key]=>[block cipher]     |
     *                  V         |                   V                         |            |                 |            |
     *    [key]=>[block cipher]   |    [key]=>  [block cipher]                 XOR<=[ciphertext]              XOR<=[ciphertext]
     *                  |         |                   |                         |                              |         
     *    [plaintext]=>XOR        |     [plaintext]=>XOR                        V                              V
     *                  |         |                   |                    [plaintext]                    [plaintext]
     *                  +---------+                   |
     *                  V                             V
     *             [ciphertext]                  [ciphertext]
     */
	GKO_Cipher(state, GKO_GetCB(state),GKO_cipher_symmetrical);	// encrypt IV
	GKO_XorWithCB(state, bp);									// XOR plaintext with chaining buffer (initially set to IV)
	GKO_SetCB(state,bp);										// store ciphertext in chaining buffer
}
LOCAL void GKO_DecryptCFB(GKO_state_t* state, uint8_t* bp)
{	uint8_t ciphertext[GKO_BLOCK_SIZE];							// ciphertext storage
	memcpy(ciphertext, bp, GKO_BLOCK_SIZE);						// backup ciphertext
	GKO_Cipher(state, GKO_GetCB(state),GKO_cipher_symmetrical);	// decrypt the IV	
	GKO_XorWithCB(state, bp);									// XOR plaintext with chaining buffer (initially set to IV)
	GKO_SetCB(state,ciphertext);								// store ciphertext in chaining buffer
}
#endif // GKO_ENABLE_CFB
#ifdef GKO_ENABLE_OFB
LOCAL void GKO_EncryptOFB(GKO_state_t* state, uint8_t* bp)
{    /* OFB Mode:  Encryption                  Encryption                Decryption
     * 
     *                [IV]                                                     [IV]                                  
     *                  |                                                        |                              
     *                  |         +-------------------+                          |           +-----------------+            
     *                  |         |                   |                          |           |                 |            
     *                  |         |                   |                          V           |                 V            
     *                  |         |                   |            [key]=> [block cipher]    |    [key]=>[block cipher]     
     *                  |         |                   |                         |            |                 |            
     *                  |         |                   |                         +------------+                 +---...
	 *                  V         |                   V                         |                              |
     *    [key]=>[block cipher]   |    [key]=>  [block cipher]                 XOR<=[ciphertext]              XOR<=[ciphertext]
     *                  |         |                   |                         |                              |         
                        +---------+                   +---...                   |                              |
	 *                  |                             |                         |                              |
     *    [plaintext]=>XOR              [plaintext]=>XOR                        V                              V
     *                  |                             |                    [plaintext]                    [plaintext]
     *                  |                             |
     *                  V                             V
     *             [ciphertext]                  [ciphertext]
     */
	uint8_t ciphertext[GKO_BLOCK_SIZE];							// ciphertext storage
	GKO_Cipher(state, GKO_GetCB(state),GKO_cipher_symmetrical); // encrypt IV
	memcpy(ciphertext, GKO_GetCB(state), GKO_BLOCK_SIZE);		// backup ciphertext
	GKO_XorWithCB(state, bp);									// XOR plaintext with chaining buffer (initially set to IV)
	GKO_SetCB(state,ciphertext);								// store ciphertext in chaining buffer
}
LOCAL void GKO_DecryptOFB(GKO_state_t* state, uint8_t* bp)
{	// symmetric encryption
	GKO_EncryptOFB(state, bp);
}
#endif // GKO_ENABLE_OFB

void GKO_Encrypt(GKO_state_t* state, uint8_t* bufx, const uint32_t block_size)
{
	uint32_t count;
	char*bp=bufx;
	uint32_t len = block_size;
	assert ((block_size % GKO_BLOCK_SIZE == 0));
	for (count=0; len > 0; bp+=GKO_BLOCK_SIZE, len-=GKO_BLOCK_SIZE)
	{	
		switch(state->encryption_mode)
		{
#ifdef GKO_ENABLE_CBC
		case GKO_mode_cbc:
			GKO_EncryptCBC(state, bp);
			break;
#endif // GKO_ENABLE_CBC
#ifdef GKO_ENABLE_CTR	
		case GKO_mode_ctr:
			GKO_EncryptCTR(state, bp);
			break;
#endif // GKO_ENABLE_CTR	
#ifdef GKO_ENABLE_ECB
		case GKO_mode_ecb:
			GKO_EncryptECB(state, bp);
			break;
#endif // GKO_ENABLE_ECB
#ifdef GKO_ENABLE_PCBC
		case GKO_mode_pcbc:
			GKO_EncryptPCBC(state, bp);
			break;
#endif // GKO_ENABLE_PCBC
#ifdef GKO_ENABLE_CFB
		case GKO_mode_cfb:
			GKO_EncryptCFB(state, bp);
			break;
#endif // GKO_ENABLE_CFB
#ifdef GKO_ENABLE_OFB
		case GKO_mode_ofb:
			GKO_EncryptOFB(state, bp);
			break;
#endif // GKO_ENABLE_OFB
		default:
			// you forgot to set an encryption mode
			assert(0);
			break;
		}
	}
}
void GKO_Decrypt(GKO_state_t* state, uint8_t* bufx, const uint32_t block_size)
{
	uint32_t count;
	char*bp=bufx;
	uint32_t len = block_size;
	assert ((block_size % GKO_BLOCK_SIZE == 0));
	for (count=0; len > 0; bp+=GKO_BLOCK_SIZE, len-=GKO_BLOCK_SIZE)
	{	
		switch(state->encryption_mode)
		{
#ifdef GKO_ENABLE_CBC
		case GKO_mode_cbc:
			GKO_DecryptCBC(state, bp);
			break;
#endif // GKO_ENABLE_CBC
#ifdef GKO_ENABLE_CTR	
		case GKO_mode_ctr:
			GKO_DecryptCTR(state, bp);
			break;
#endif // GKO_ENABLE_CTR	
#ifdef GKO_ENABLE_ECB
		case GKO_mode_ecb:
			GKO_DecryptECB(state, bp);
			break;
#endif // GKO_ENABLE_ECB
#ifdef GKO_ENABLE_PCBC
		case GKO_mode_pcbc:
			GKO_DecryptPCBC(state, bp);
			break;
#endif // GKO_ENABLE_PCBC
#ifdef GKO_ENABLE_CFB
		case GKO_mode_cfb:
			GKO_DecryptCFB(state, bp);
			break;
#endif // GKO_ENABLE_CFB
#ifdef GKO_ENABLE_OFB
		case GKO_mode_ofb:
			GKO_DecryptOFB(state, bp);
			break;
#endif // GKO_ENABLE_OFB
		default:
			// you forgot to set an encryption mode
			assert(0);
			break;
		}
	}
}
void GKO_InitState(GKO_state_t* state, const uint8_t key[], const uint8_t iv[]) 
{
	int ix;

#ifdef	GKO_NEEDS_IV
	state->iv_buffer.next_ele=0;								// needed for CTR mode
#else
	if (iv != NULL)												// sanity check
	{ assert(0); }
#endif // GKO_NEEDS_IV

#ifdef	GKO_NEEDS_IV
	////////////////////
	// initialize chain block data, used for CBC etc.
	if (iv != NULL)
	{	// first chain block is IV
		memcpy(state->iv_buffer.bytes,iv,GKO_IV_BUFFER_SIZE);
		memcpy(state->chaining_buffer.bytes,iv,GKO_IV_BUFFER_SIZE);
	}

	// expand the keys
#endif // GKO_NEEDS_IV
	GKO_ExpandKeys(state, key);

	// create byte key-based exchanges (swaps) for the block size buffers
	for(ix=0;ix < GKO_BLOCK_SIZE; ix++)
		state->exchanges.bytes[ix]=ix;

	// shuffle byte exchanges
	KeyedShuffle(state->expanded_keys.bytes, state->exchanges.bytes, GKO_BLOCK_SIZE);
	
	assert (state->encryption_mode > GKO_mode_begin && state->encryption_mode < GKO_mode_end);
	return;
}
LOCAL void GKO_ExpandKeys(GKO_state_t* state, const uint8_t key[])
{ 
	/*	TOMASELLO Key Expansion Algorithm (TKEA)
	*	The first GKO_KEY_NELTS contain the cipher key itself
	*	All keys that follow are the next cipher key element, rotated left N number of bits,
	*		xor'ed with the round-key salt.
	*	The round-key salt is comprised of a round constant (rsbox) xor the next cipher key
	*/
	int ix, ndx = 0, shift = 0;
	uint8_t key_salt=0, salt_ndx=0;
	uint8_t prng_tab[GKO_EXP_KEY_TBL_SIZE];
	for (ix = 0; ix < GKO_EXP_KEY_TBL_SIZE; ix++)
	{
		if (ndx == GKO_KEY_NELTS)
		{
			assert (salt_ndx < GKO_KEY_NELTS);					// never reached
			key_salt = gko_rsbox[key_salt] ^ key[salt_ndx++];	// create next round salt
			ndx = 0;											// restart the next-key index
			shift++;											// next rotate value
		}
		// record the new key
		state->expanded_keys.bytes[ix] = _rotl8(key[ndx++],shift) ^ key_salt;
		// create our pseudo-random sorting hat
		prng_tab[ix] = gko_rsbox[ix] ^ state->expanded_keys.bytes[ix];
	}
	// shuffle the expanded keys across the entire key-space
	KeyedShuffle(prng_tab,state->expanded_keys.bytes, GKO_EXP_KEY_TBL_SIZE);
}
LOCAL void GKO_Cipher(GKO_state_t* state, uint8_t* bp, GKO_Cipher_Direction_t direction)
{
	int16_t round;
	const uint8_t* round_key;
	const uint8_t* key_tab = state->expanded_keys.bytes;
	
	if (direction == GKO_cipher_forward)
	{
		GKO_XORBytes(state->exchanges.bytes, bp);
		GKO_ShuffleBytes(state->exchanges.bytes, bp);

		for (round = 0; round < GKO_NROUNDS - 1; round++)
		{
			round_key = &key_tab[round * GKO_KEY_LEN];
			GKO_SubBytes(bp);						
			GKO_SboxMaskBytes(round_key, bp);		
			GKO_CipherMaskBytes(round_key, bp);		
			GKO_ShuffleBits(bp);					
			GKO_ShuffleBytes(state->exchanges.bytes, bp);	
			GKO_XORBytes(state->exchanges.bytes, bp);		
		}

		GKO_ShuffleBytes(state->exchanges.bytes, bp);		
		GKO_CipherMaskBytes(&key_tab[round * GKO_KEY_LEN], bp);
	}

	else if (direction == GKO_cipher_backward)
	{
		GKO_CipherMaskBytes(&key_tab[GKO_EXP_KEY_TBL_SIZE - GKO_KEY_LEN], bp);
		GKO_InvShuffleBytes(state->exchanges.bytes, bp);	

		for (round = GKO_NROUNDS - 1 - 1; round >= 0; round--)
		{
			round_key = &key_tab[round * GKO_KEY_LEN];
			GKO_InvXORBytes(state->exchanges.bytes, bp);	
			GKO_InvShuffleBytes(state->exchanges.bytes, bp);
			GKO_InvShuffleBits(bp);							
			GKO_CipherMaskBytes(round_key, bp);				
			GKO_SboxMaskBytes(round_key, bp);				
			GKO_InvSubBytes(bp);							
		}

		GKO_InvShuffleBytes(state->exchanges.bytes, bp);	
		GKO_InvXORBytes(state->exchanges.bytes, bp);		
	}
}

#define POPHEAD_MASK 0xfc
#define POPHEAD_SHIFT 0x2
#define GLUETAIL_SHIFT 0x06
#define POPTAIL_MASK 0x3f
#define POPTAIL_SHIFT 0x2
#define GLUEHEAD_SHIFT 0x6
LOCAL uint8_t PopHead(uint8_t* ch)
{
	uint8_t head = (*ch) & POPHEAD_MASK;	/* save the top N bits to the context buffer */
	return head >> POPHEAD_SHIFT;			/* return head bits ready for gluing */
}
LOCAL uint8_t GlueTail(uint8_t* ch, uint8_t tail)
{
	uint8_t tmp = *ch;				/* make a copy to get the head from */
	(*ch) <<= GLUETAIL_SHIFT;		/* shift the byte over to make room for tail patch */
	(*ch) |= tail;					/* affix the tail */
	return PopHead(&tmp);			/* get the head bits from this byte */
}
LOCAL uint8_t PopTail(uint8_t* ch)
{
	uint8_t tail = (*ch) & POPTAIL_MASK;	/* save the bottom N bits to the context buffer */
	return tail << POPTAIL_SHIFT;				
}
LOCAL uint8_t GlueHead(uint8_t* ch, uint8_t tail)
{
	uint8_t tmp = *ch;				/* make a copy to get the head from */
	(*ch) >>= GLUEHEAD_SHIFT;		/* shift the byte over to make room for head patch */
	(*ch) |= tail;					// add tail to the head of this byte
	return PopTail(&tmp);
}
LOCAL void GKO_ShuffleBits(uint8_t buff[])
{
	/* TOMASELLO BitShuffle (TBS)
	* 128 Bits are rotated as follows (assuming 3bit rotate)
	*   [y][y][y][y] [y][y][y][y] <== byte 0
	*   [x][x][x][x] [x][x][x][x] <== byte 1
	*   [z][z][z][z] [z][z][z][z] <== byte 2
	*               .
	*               .
	*               .
    *
	*                       +-----+
	*                       |     |
	*                    V--V--V  |
	*   [y][y][y][y] [y][Z][Z][Z] |
	*    ^--^--^                  |
	*      |                      |
	*      +----------------+     |
	*                       |     |
	*                    V--V--V  |
	*   [x][x][x][x] [x][Y][Y][Y] |
	*    ^--^--^                  |
	*      |                      |
	*      +----------------+     |
	*                       |     |
	*                    V--V--V  |
	*   [z][z][z][z] [z][X][X][X] | continue to rotate until the last byte
	*    ^--^--^                  | Then circle back to patch the first byte 
	*      |                      |
	*      +----------------------+
	*/
#ifdef GKO_SPEED_OVER_SIZE
	uint8_t head;
	head = PopHead(&buff[0x0]);
	head = GlueTail(&buff[0x1], head);
	head = GlueTail(&buff[0x2], head);
	head = GlueTail(&buff[0x3], head);
	head = GlueTail(&buff[0x4], head);
	head = GlueTail(&buff[0x5], head);
	head = GlueTail(&buff[0x6], head);
	head = GlueTail(&buff[0x7], head);
	head = GlueTail(&buff[0x8], head);
	head = GlueTail(&buff[0x9], head);
	head = GlueTail(&buff[0xa], head);
	head = GlueTail(&buff[0xb], head);
	head = GlueTail(&buff[0xc], head);
	head = GlueTail(&buff[0xd], head);
	head = GlueTail(&buff[0xe], head);
	head = GlueTail(&buff[0xf], head);
	GlueTail(&buff[0x0], head);
#else
	int32_t ix;
	uint8_t head;

	head = PopHead(&buff[0x0]);
	for (ix = 1; ix < GKO_BLOCK_SIZE; ix++)
	{ 	
		head = GlueTail(&buff[ix], head);
	}
	GlueTail(&buff[0x0], head);

#endif
}
LOCAL void GKO_InvShuffleBits(uint8_t buff[])
{
#ifdef GKO_SPEED_OVER_SIZE
	uint8_t tail;
	tail = PopTail(&buff[0x0]);
	tail = GlueHead(&buff[0xf], tail);
	tail = GlueHead(&buff[0xe], tail);
	tail = GlueHead(&buff[0xd], tail);
	tail = GlueHead(&buff[0xc], tail);
	tail = GlueHead(&buff[0xb], tail);
	tail = GlueHead(&buff[0xa], tail);
	tail = GlueHead(&buff[0x9], tail);
	tail = GlueHead(&buff[0x8], tail);
	tail = GlueHead(&buff[0x7], tail);
	tail = GlueHead(&buff[0x6], tail);
	tail = GlueHead(&buff[0x5], tail);
	tail = GlueHead(&buff[0x4], tail);
	tail = GlueHead(&buff[0x3], tail);
	tail = GlueHead(&buff[0x2], tail);
	tail = GlueHead(&buff[0x1], tail);
	GlueHead(&buff[0x0], tail);
#else
	int32_t ix;
	uint8_t tail;

	tail = PopTail(&buff[0x0]);
	for (ix = GKO_BLOCK_SIZE - 1; ix > 0; ix--)
	{ 	
		tail = GlueHead(&buff[ix], tail);
	}
	GlueHead(&buff[0x0], tail);
#endif
}
LOCAL void GKO_CipherMaskBytes(const uint8_t round_key[], uint8_t* bp)
{
#ifdef GKO_SPEED_OVER_SIZE
	bp[0x0] ^= round_key[0x0];PUMPKIN_Recorder(round_key[0x0], 0);
	bp[0x1] ^= round_key[0x1];PUMPKIN_Recorder(round_key[0x1], 0);
	bp[0x2] ^= round_key[0x2];PUMPKIN_Recorder(round_key[0x2], 0);
	bp[0x3] ^= round_key[0x3];PUMPKIN_Recorder(round_key[0x3], 0);
	bp[0x4] ^= round_key[0x4];PUMPKIN_Recorder(round_key[0x4], 0);
	bp[0x5] ^= round_key[0x5];PUMPKIN_Recorder(round_key[0x5], 0);
	bp[0x6] ^= round_key[0x6];PUMPKIN_Recorder(round_key[0x6], 0);
	bp[0x7] ^= round_key[0x7];PUMPKIN_Recorder(round_key[0x7], 0);
	bp[0x8] ^= round_key[0x8];PUMPKIN_Recorder(round_key[0x8], 0);
	bp[0x9] ^= round_key[0x9];PUMPKIN_Recorder(round_key[0x9], 0);
	bp[0xa] ^= round_key[0xa];PUMPKIN_Recorder(round_key[0xa], 0);
	bp[0xb] ^= round_key[0xb];PUMPKIN_Recorder(round_key[0xb], 0);
	bp[0xc] ^= round_key[0xc];PUMPKIN_Recorder(round_key[0xc], 0);
	bp[0xd] ^= round_key[0xd];PUMPKIN_Recorder(round_key[0xd], 0);
	bp[0xe] ^= round_key[0xe];PUMPKIN_Recorder(round_key[0xe], 0);
	bp[0xf] ^= round_key[0xf];PUMPKIN_Recorder(round_key[0xf], 0);
#else
	uint32_t key_element;
	uint8_t mask;
	for (key_element = 0; key_element < GKO_KEY_LEN; key_element++)
	{
		mask = round_key[key_element];
		PUMPKIN_Recorder(mask, 0);		// record this mask for analysis only
		bp[key_element] ^= mask;		
	}
#endif
}
LOCAL void GKO_SubBytes(uint8_t bp[])
{
#ifdef GKO_SPEED_OVER_SIZE
	bp[0x0] = gko_sbox[bp[0x0]];
	bp[0x1] = gko_sbox[bp[0x1]];
	bp[0x2] = gko_sbox[bp[0x2]];
	bp[0x3] = gko_sbox[bp[0x3]];
	bp[0x4] = gko_sbox[bp[0x4]];
	bp[0x5] = gko_sbox[bp[0x5]];
	bp[0x6] = gko_sbox[bp[0x6]];
	bp[0x7] = gko_sbox[bp[0x7]];
	bp[0x8] = gko_sbox[bp[0x8]];
	bp[0x9] = gko_sbox[bp[0x9]];
	bp[0xa] = gko_sbox[bp[0xa]];
	bp[0xb] = gko_sbox[bp[0xb]];
	bp[0xc] = gko_sbox[bp[0xc]];
	bp[0xd] = gko_sbox[bp[0xd]];
	bp[0xe] = gko_sbox[bp[0xe]];
	bp[0xf] = gko_sbox[bp[0xf]];
#else
	int ix;
	for (ix = 0; ix < GKO_BLOCK_SIZE; ix++)
		// substitute bytes
		bp[ix] = gko_sbox[bp[ix]];
#endif
}
LOCAL void GKO_InvSubBytes(uint8_t bp[])
{
#ifdef GKO_SPEED_OVER_SIZE
	bp[0x0] = gko_rsbox[bp[0x0]];
	bp[0x1] = gko_rsbox[bp[0x1]];
	bp[0x2] = gko_rsbox[bp[0x2]];
	bp[0x3] = gko_rsbox[bp[0x3]];
	bp[0x4] = gko_rsbox[bp[0x4]];
	bp[0x5] = gko_rsbox[bp[0x5]];
	bp[0x6] = gko_rsbox[bp[0x6]];
	bp[0x7] = gko_rsbox[bp[0x7]];
	bp[0x8] = gko_rsbox[bp[0x8]];
	bp[0x9] = gko_rsbox[bp[0x9]];
	bp[0xa] = gko_rsbox[bp[0xa]];
	bp[0xb] = gko_rsbox[bp[0xb]];
	bp[0xc] = gko_rsbox[bp[0xc]];
	bp[0xd] = gko_rsbox[bp[0xd]];
	bp[0xe] = gko_rsbox[bp[0xe]];
	bp[0xf] = gko_rsbox[bp[0xf]];
#else
	int ix;
	for (ix = GKO_BLOCK_SIZE - 1; ix >= 0; ix--)
		// invert masked substitute
		bp[ix] = gko_rsbox[bp[ix]];
#endif
}
LOCAL void GKO_SwapBytes(uint8_t* b1, uint8_t* b2)
{
	uint8_t tmp;
	tmp = *b1; 
	*b1 = *b2; 
	*b2 = tmp; 
}
LOCAL void GKO_ShuffleBytes (const uint8_t exchanges[], uint8_t bp[]) 
{ 
#ifdef GKO_SPEED_OVER_SIZE
	GKO_SwapBytes(&bp[0xf], &bp[exchanges[0x0]]);
	GKO_SwapBytes(&bp[0xe], &bp[exchanges[0x1]]);
	GKO_SwapBytes(&bp[0xd], &bp[exchanges[0x2]]);
	GKO_SwapBytes(&bp[0xc], &bp[exchanges[0x3]]);
	GKO_SwapBytes(&bp[0xb], &bp[exchanges[0x4]]);
	GKO_SwapBytes(&bp[0xa], &bp[exchanges[0x5]]);
	GKO_SwapBytes(&bp[0x9], &bp[exchanges[0x6]]);
	GKO_SwapBytes(&bp[0x8], &bp[exchanges[0x7]]);
	GKO_SwapBytes(&bp[0x7], &bp[exchanges[0x8]]);
	GKO_SwapBytes(&bp[0x6], &bp[exchanges[0x9]]);
	GKO_SwapBytes(&bp[0x5], &bp[exchanges[0xa]]);
	GKO_SwapBytes(&bp[0x4], &bp[exchanges[0xb]]);
	GKO_SwapBytes(&bp[0x3], &bp[exchanges[0xc]]);
	GKO_SwapBytes(&bp[0x2], &bp[exchanges[0xd]]);
	GKO_SwapBytes(&bp[0x1], &bp[exchanges[0xe]]);
#else
	/* modified Fisher–Yates shuffle.
	* We use a table of keys and/or derivatives to provide the pseudorandom numbers used for the shuffle.
	* It is intended and desirable that the sequence not be truly pseudorandom as we would like the
	*	supplied cipher key to have a distinct influence on the shuffle order. That is, each shuffle
	*	is different based upon the key.
	*/
	int32_t i, n;
	uint8_t tmp;

	for (i = GKO_BLOCK_SIZE - 1; i > 0; i--)
	{	// Pick a random index from 0 to i 
		n = exchanges[GKO_BLOCK_SIZE - 1 - i];
		assert(i >= 0 && i < GKO_BLOCK_SIZE && n >= 0 && n < GKO_BLOCK_SIZE);

		// Swap bp[i] with the element at random index 
		tmp = bp[i]; 
		bp[i] = bp[n]; 
		bp[n] = tmp; 
	} 
#endif
} 
LOCAL void GKO_InvShuffleBytes (const uint8_t exchanges[], uint8_t bp[]) 
{ 
#ifdef GKO_SPEED_OVER_SIZE
	GKO_SwapBytes(&bp[0x1], &bp[exchanges[0xe]]);
	GKO_SwapBytes(&bp[0x2], &bp[exchanges[0xd]]);
	GKO_SwapBytes(&bp[0x3], &bp[exchanges[0xc]]);
	GKO_SwapBytes(&bp[0x4], &bp[exchanges[0xb]]);
	GKO_SwapBytes(&bp[0x5], &bp[exchanges[0xa]]);
	GKO_SwapBytes(&bp[0x6], &bp[exchanges[0x9]]);
	GKO_SwapBytes(&bp[0x7], &bp[exchanges[0x8]]);
	GKO_SwapBytes(&bp[0x8], &bp[exchanges[0x7]]);
	GKO_SwapBytes(&bp[0x9], &bp[exchanges[0x6]]);
	GKO_SwapBytes(&bp[0xa], &bp[exchanges[0x5]]);
	GKO_SwapBytes(&bp[0xb], &bp[exchanges[0x4]]);
	GKO_SwapBytes(&bp[0xc], &bp[exchanges[0x3]]);
	GKO_SwapBytes(&bp[0xd], &bp[exchanges[0x2]]);
	GKO_SwapBytes(&bp[0xe], &bp[exchanges[0x1]]);
	GKO_SwapBytes(&bp[0xf], &bp[exchanges[0x0]]);
#else
	int32_t i, n;
	uint8_t tmp;

	for (i = 1; i < GKO_BLOCK_SIZE; i++)
	{ 	// Pick a random index from 0 to i 
		n = exchanges[GKO_BLOCK_SIZE - i - 1];
		assert(i >= 0 && i < GKO_BLOCK_SIZE && n >= 0 && n < GKO_BLOCK_SIZE);

		// Swap bp[i] with the element at random index 
		tmp = bp[i]; 
		bp[i] = bp[n]; 
		bp[n] = tmp; 
	}
#endif
} 
LOCAL void GKO_XORBytes (const uint8_t exchanges[], uint8_t bp[]) 
{ 
	bp[exchanges[0x0]] ^= bp[exchanges[0x1]];
	bp[exchanges[0x2]] ^= bp[exchanges[0x3]];
	bp[exchanges[0x4]] ^= bp[exchanges[0x5]];
	bp[exchanges[0x6]] ^= bp[exchanges[0x7]];

	bp[exchanges[0x1]] ^= bp[exchanges[0x2]];
	bp[exchanges[0x3]] ^= bp[exchanges[0x4]];
	bp[exchanges[0x5]] ^= bp[exchanges[0x6]];
	bp[exchanges[0x7]] ^= bp[exchanges[0x0]];
} 
LOCAL void GKO_InvXORBytes (const uint8_t exchanges[], uint8_t bp[]) 
{ 
	bp[exchanges[0x7]] ^= bp[exchanges[0x0]];
	bp[exchanges[0x5]] ^= bp[exchanges[0x6]];
	bp[exchanges[0x3]] ^= bp[exchanges[0x4]];
	bp[exchanges[0x1]] ^= bp[exchanges[0x2]];

	bp[exchanges[0x6]] ^= bp[exchanges[0x7]];
	bp[exchanges[0x4]] ^= bp[exchanges[0x5]];
	bp[exchanges[0x2]] ^= bp[exchanges[0x3]];
	bp[exchanges[0x0]] ^= bp[exchanges[0x1]];
} 
LOCAL void GKO_SboxMaskBytes(const uint8_t round_key[], uint8_t bp[])
{
#ifdef GKO_SPEED_OVER_SIZE
	bp[0xf] ^= gko_sbox[round_key[0xf]];
	bp[0xe] ^= gko_sbox[round_key[0xe]];
	bp[0xd] ^= gko_sbox[round_key[0xd]];
	bp[0xc] ^= gko_sbox[round_key[0xc]];
	bp[0xb] ^= gko_sbox[round_key[0xb]];
	bp[0xa] ^= gko_sbox[round_key[0xa]];
	bp[0x9] ^= gko_sbox[round_key[0x9]];
	bp[0x8] ^= gko_sbox[round_key[0x8]];
	bp[0x7] ^= gko_sbox[round_key[0x7]];
	bp[0x6] ^= gko_sbox[round_key[0x6]];
	bp[0x5] ^= gko_sbox[round_key[0x5]];
	bp[0x4] ^= gko_sbox[round_key[0x4]];
	bp[0x3] ^= gko_sbox[round_key[0x3]];
	bp[0x2] ^= gko_sbox[round_key[0x2]];
	bp[0x1] ^= gko_sbox[round_key[0x1]];
	bp[0x0] ^= gko_sbox[round_key[0x0]];
#else
	int32_t ix;

	for (ix = GKO_BLOCK_SIZE - 1; ix >= 0; ix--)
	{
		bp[ix] ^= gko_sbox[round_key[ix]];
	}
#endif
}
LOCAL void KeyedShuffle(const uint8_t table[], uint8_t key[], const uint32_t size)
{
	/* modified Fisher–Yates shuffle.
	* We use a table of keys and/or derivatives to provide the pseudorandom numbers used for the shuffle.
	* It is intended and desirable that the sequence not be truly pseudorandom as we would like the
	*	supplied cipher key to have a distinct influence on the shuffle order. That is, each shuffle
	*	is different based upon the key.
	*/
	uint32_t i, n;
	uint8_t tmp;

	for (i = size - 1; i > 0; i--)
	{	// Pick a random index from 0 to i 
		n = table[size - 1 - i] % (i + 1);
		assert(i >= 0 && i < size && n >= 0 && n < size);

		// Swap bp[i] with the element at random index 
		tmp = key[i];
		key[i] = key[n];
		key[n] = tmp;
	}
}

static const uint8_t gko_sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t gko_rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
