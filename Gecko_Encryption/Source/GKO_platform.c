#include <stdlib.h>			// RAND_MAX
#include <assert.h>
#include "GKO_platform.h"


#if WIN32
// _rotl8(val,n): you must enable Compiler Intrinsics in the C optimizations tab for _rotl8
//	Otherwise, you can use the function below which is nearly as fast.
#define BYTE_ORDER LITTLE_ENDIAN
#else
// Use can use my version here, or use your platforms version if it is faster
uint8_t GKO_RotateLeft(uint8_t val, int N) 
{
	uint8_t  num = val;
	int pos = N;
	/*
		Speed Test complete, _rotl took 7.463000 seconds to execute
		Speed Test complete, rotateLeft took 7.771000 seconds to execute
	*/
	return (val << N)|(val >> (CHAR_BIT - N)); 
}
#endif
