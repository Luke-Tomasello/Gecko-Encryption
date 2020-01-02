#ifndef _GKO_TEST_DATA_INCLUDED_
#define _GKO_TEST_DATA_INCLUDED_

/*
 * Gecko test data.
 * test data located in Gecko_test_data.c
 */
extern const uint8_t Kipling[1497];			// strlen + 16
extern const uint8_t LoremIpsum[443];		// strlen + 16
extern const uint8_t TheTruth[122];			// strlen + 16
extern const uint8_t Perrault[3644];		// strlen + 16

// Gecko keys and IV

extern const uint8_t gko_key[];
extern const uint8_t gko_iv[];

// AES keys and IV
extern uint8_t aes_key[];
extern uint8_t aes_iv[];

#endif // _GKO_TEST_DATA_INCLUDED_