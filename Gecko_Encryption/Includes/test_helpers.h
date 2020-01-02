#ifndef _GKO_HELPERS_INCLUDED_
#define _GKO_HELPERS_INCLUDED_
#include <stdio.h>
#include "stdint.h"
#define BFR_GARBAGE_FILL 0xFF						// memory garbage fill
// padding helpers
uint16_t GUTL_PadBlockRaw(uint8_t* bp, uint16_t len, uint8_t is_lastblock);
uint16_t GUTL_UnPadBlockRaw(uint8_t* bp, uint16_t len);

#endif // _GKO_HELPERS_INCLUDED_


