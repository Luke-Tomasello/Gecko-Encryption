#include "test_helpers.h"

#define GUTL_BLOCK_SIZE 16
uint16_t GUTL_PadBlockRaw(uint8_t* bp, uint16_t len, uint8_t is_lastblock)
{	// we were called because the data is  < 16 bytes
	// We will add padding bytes, where each pad byte the the number of padding bytes added
	// We will use PKCS#7 padding, decribed in Section 10.3 of RSA PKCS#7.
	int padval=0;

	if (len % GUTL_BLOCK_SIZE != 0)
		padval = GUTL_BLOCK_SIZE - (len % GUTL_BLOCK_SIZE);
	else if (len == 0)
		padval = GUTL_BLOCK_SIZE;
	else
		padval = 0;
	
	memset(&bp[len], padval, padval);

	// add padding for the last block if no other padding was needed
	if (padval == 0 && is_lastblock == 1)
	{
		memset(&bp[len], GUTL_BLOCK_SIZE, GUTL_BLOCK_SIZE);
		return len + GUTL_BLOCK_SIZE;
	}

	// return number of padding bytes added
	return len + padval;
}
uint16_t GUTL_UnPadBlockRaw(uint8_t* bp, uint16_t len)
{	// remove PKCS#7 padding and return the new data size
	unsigned ix;

	// this value should be the last padding byte, it also describes how many padding bytes there are.
	uint8_t last_char = bp[len-1];

	// buffer not padded
	if (last_char > GUTL_BLOCK_SIZE || last_char == 0)
		return len;

	// verify all pading bytes
	for (ix=len-last_char; ix < len; ix++)
	{
		if (bp[ix] != last_char)
			// not padding
			return len;
	}

	// okay, we've verified the padding bytes, now remove them
	// memclear all padding leaving only the original plaintext message
	memset(&bp[len - last_char], 0, last_char);

	// return the original plaintext message size
	return len - last_char;
}