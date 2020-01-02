#ifndef _GKO_INCLUDED_
#define _GKO_INCLUDED_

#include "GKO_platform.h"							// platform dependent utilities

#define GKO_BLOCK_SIZE 16							// Gecko Block Size in bytes
#define GKO_DESCRIPTOR_SIZE 16						// Descriptor between sender and recipient. at a minimum, contains padding byte count
#define GKO_IV_BUFFER_SIZE 16						// enough room for 16 bit IV. 

// You must define at least one of these for your implementation
//GKO_ENABLE_CBC									// Cipher Block Chaining (CBC)
//GKO_ENABLE_CFB									// Cipher Feedback (CFB)
//GKO_ENABLE_CTR									// Counter (CTR)
//GKO_ENABLE_ECB									// Electronic Codebook (ECB)
//GKO_ENABLE_OFB									// Output Feedback (OFB)
//GKO_ENABLE_PCBC									// Propagating Cipher Block Chaining (PCBC)

// you will also need to define at most one of:
//_GKO256											// 256 bit key
//_GKO192											// 192 bit key
//_GKO128											// 128 bit key

#if defined(GKO_ENABLE_CBC) || defined(GKO_ENABLE_CTR) || defined(GKO_ENABLE_PCBC) || defined(GKO_ENABLE_CFB)  || defined(GKO_ENABLE_OFB)
#define GKO_NEEDS_IV 
#endif // GKO_NEEDS_IV 

#if defined(_GKO256)
#define GKO_KEY_LEN (GKO_BLOCK_SIZE)
#define GKO_NROUNDS 15
#define GKO_KEY_NELTS 32
#define GKO_EXP_KEY_TBL_SIZE 240
#elif defined(_GKO192)
#define GKO_KEY_LEN (GKO_BLOCK_SIZE)	// what dn't we understand here? 13*16==208
#define GKO_NROUNDS 13
#define GKO_KEY_NELTS 24
#define GKO_EXP_KEY_TBL_SIZE 208
#elif defined(_GKO128)
#define GKO_KEY_LEN GKO_BLOCK_SIZE							// The number of bytes in a key.
#define GKO_NROUNDS 11										// The number of rounds in Gecko Cipher.
#define GKO_KEY_NELTS 16									// The number of bytes in a key
#define GKO_EXP_KEY_TBL_SIZE 176							// GKO uses an expanded key table of size N
#endif

typedef enum {
	GKO_mode_begin =  0x00,									// valid modes are greater than GKO_mode_begin
#ifdef GKO_ENABLE_CBC
	GKO_mode_cbc =  0x01,									// Cipher Block Chaining (CBC)
#endif // GKO_ENABLE_CBC
#ifdef GKO_ENABLE_CTR	
	GKO_mode_ctr =  0x02,									// Counter (CTR)
#endif // GKO_ENABLE_CTR	
#ifdef GKO_ENABLE_ECB
	GKO_mode_ecb =  0x03,									// Electronic Codebook (ECB)
#endif // GKO_ENABLE_ECB
#ifdef GKO_ENABLE_PCBC
	GKO_mode_pcbc = 0x04,									// Propagating Cipher Block Chaining (PCBC)
#endif // GKO_ENABLE_PCBC
#ifdef GKO_ENABLE_CFB
	GKO_mode_cfb =  0x05,									// Cipher Feedback (CFB)
#endif // GKO_ENABLE_CFB
#ifdef GKO_ENABLE_OFB
	GKO_mode_ofb =  0x06,									// Output Feedback (OFB)
#endif // GKO_ENABLE_OFB
	GKO_mode_end,											// valid modes are less than GKO_mode_end
} GKO_encryption_mode_t;

typedef enum {
	GKO_cipher_forward = 0x01,								// cipher in one direction, 'forward'
	GKO_cipher_backward = 0x02,								// reverse the cipher 'backward'
	GKO_cipher_symmetrical = GKO_cipher_forward,			// certain modes do not change the direction, e.g., CTR, OFB, CFB, etc.
} GKO_Cipher_Direction_t;

typedef struct
{
	GKO_encryption_mode_t encryption_mode;					// mode: CBC, CTR, ECB, etc.
#ifdef GKO_NEEDS_IV 
	// crypto key buffer passed in
	struct {
		uint8_t bytes[GKO_IV_BUFFER_SIZE];					// 128 bit iv
		int32_t next_ele;									// next one to use
	} iv_buffer;
#endif // GKO_NEEDS_IV 
	struct {
		uint8_t bytes[GKO_EXP_KEY_TBL_SIZE];				// 176/208/240 expanded keys
	} expanded_keys;

	// crypto buffer from last encrypted block
	// Used as mask values for next encryption pass
	struct  {
		uint8_t bytes[GKO_BLOCK_SIZE];						// put encrypted bytes here,used for next encryption
	} chaining_buffer;											

	struct  {
		uint8_t bytes[GKO_BLOCK_SIZE];						// stores byte exchanges (swaps) for the input blocks
	} exchanges;											
} GKO_state_t;

// BASIC encryption/decryption GECKO.C
void GKO_InitState(GKO_state_t* state, const uint8_t key[], const uint8_t iv[]);
void GKO_Encrypt(GKO_state_t* state, uint8_t* buff, const uint32_t block_size);
void GKO_Decrypt(GKO_state_t* state, uint8_t* buff, const uint32_t block_size);

#endif // _GKO_INCLUDED_

