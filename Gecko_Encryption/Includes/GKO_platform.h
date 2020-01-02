#ifndef _GKO_PLATFORM_INCLUDED_
#define _GKO_PLATFORM_INCLUDED_
#include <stdio.h>
#include "stdint.h"

// If you don't have the Compiler Intrinsics for _rotl8(), you can use my GKO_RotateLeft() function
//	which is nearly as fast.
uint8_t GKO_RotateLeft(uint8_t val, int n);

// used with ntohl and ntohl to convert the long to a string of bytes
typedef union  {
	uint8_t bytes[4];
	uint32_t dword;
} GKO_quartet_t;

#endif // _GKO_PLATFORM_INCLUDED_


