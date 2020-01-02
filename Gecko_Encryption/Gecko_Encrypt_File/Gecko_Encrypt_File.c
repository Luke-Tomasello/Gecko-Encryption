// Gecko_Encryption_C_Version2.cpp : Defines the entry point for the console application.
//

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
#include <errno.h> 

#include "stdint.h"
#include "Gecko.h"			// main gecko include
#include "test_helpers.h"	// padding helpers

// BOOL
typedef uint8_t bool; // no bool in 'C'
#define true 1
#define false 0

static char buff[512];

// DATA TYPES
typedef enum Operations { ENCRYPT, DECRYPT, IO_TEST } Mode;

// TEST: create a temp key
const uint8_t GKO_key128[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
const uint8_t GKO_iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
const int GKO_key128Nelts = (sizeof(GKO_key128) / sizeof(GKO_key128[0]));
const int GKO_ivNelts = (sizeof(GKO_iv) / sizeof(GKO_iv[0]));

void DoMainOperation(FILE* fh, char* buff, Mode mode);
int _cdecl _tmain(int argc, char* argv[])
{
	// int fh;
	FILE* fh; errno_t err;
	enum Mode mode;

	// test command line format
	if (argc < 3)
	{
		printf("Usage: Gecko [-d|-e] filename\n");
		return 1;
	}

	// get the command args
	if (!strcmp((const char*)argv[1], "-e"))
	{
		mode = ENCRYPT;
	}
	else if (!strcmp((const char*)argv[1], "-d"))
	{
		mode = DECRYPT;
	}
	else if (!strcmp((const char*)argv[1], "-io"))
	{
		mode = IO_TEST;
	}
	else
	{
		printf("illegal mode\n");
		printf("Usage: Gecko [-d|-e] filename\n");
		return 1;
	}

	// does the file exist
	if (_access(argv[2], 0) == 0) {
		// file exists
	}
	else {
		// file doesn't exist
		printf("File %s not found.\n", argv[2]);
		return -1;
	}

	// optimization 2: buffered i/o is much better
	//	saves 1.085 seconds, or a 11.531512381762% speedup (IO_TEST)
	// 8.324000 is a 11.531512381762% decrease of 9.409000.
	err = fopen_s(&fh, argv[2], "r+bR");
	if (err != 0)
		printf("Open failed on file: %s\n", argv[2]);
	else
	{
		// give some status
		printf("Open succeeded on file: %s\n", argv[2]);
		if (mode == ENCRYPT) printf("Encrypting...");
		if (mode == DECRYPT) printf("Decrypting...");

		if (mode == IO_TEST)
		{
			int kx;
			clock_t start, end;
			double cpu_time_used;

			printf("Running I/O Test (buffered i/o) ...");
			start = clock();
			for (kx = 0; kx < 128; kx++)
			{
				rewind(fh);							// go to the beginning of the file
				DoMainOperation(fh, buff, mode);	// do it
			}
			end = clock();
			cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
			printf("\nloop (I/O, 128) took %f seconds to execute\n", cpu_time_used);
			return;
		}
		else
		{
			clock_t start, end;
			double cpu_time_used;
			start = clock();
			DoMainOperation(fh, buff, mode);
			end = clock();
			cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
			printf("\n%s took %f seconds to execute\n", (mode == ENCRYPT) ? "encryption" : (mode == DECRYPT) ? "decryption" : "task", cpu_time_used);
		}

		printf("Done.\n");
		// and cleanup
		fclose(fh);
	}

	return 0;
}
size_t ReadForUpdate(void* buffer, size_t size, size_t count, FILE* stream, fpos_t* pos)
{
	int fgetpos_err = fgetpos(stream, pos); assert(fgetpos_err == 0);
	if (fgetpos_err != 0) return 0;
	return fread(buffer, size, count, stream);
}


size_t WriteForUpdate(void* buffer, size_t size, size_t count, FILE* stream, fpos_t* pos)
{
	size_t count_written = 0;
	int fsetpos_err;
	int fgetpos_err;

	// rewind to the position to before the read
	fsetpos_err = fsetpos(stream, pos); assert(fsetpos_err == 0);

	// write the data
	count_written = fwrite(buffer, size, count, stream);

	// get the current position
	// Microsoft docs
	// When the "r+", "w+", or "a+" access type is specified, both reading and writing are allowed (the file is said to be open for "update"). 
	// However, when you switch between reading and writing, there must be an intervening fflush, fsetpos, fseek, or rewind operation. 
	// The current position can be specified for the fsetpos or fseek operation, if desired.
	fgetpos_err = fgetpos(stream, pos);
	assert(fgetpos_err == 0);

	// set the new position
	fsetpos_err = fsetpos(stream, pos);
	assert(fsetpos_err == 0);

	return count_written;
}

void DoMainOperation(FILE* fh, char* buff, Mode mode)
{
	__int64 read;
	fpos_t fpos;
	int fseek_err;
	__int64 fileSize;
	GKO_state_t state;


	if (mode != IO_TEST)
	{
		// okay, initialize the state
		GKO_InitState(&state, GKO_key128, GKO_iv);											
	}

	// determine file size so we do not need to rely upon feof()
	fseek_err = _fseeki64(fh, 0, SEEK_END); assert(fseek_err == 0);
	fileSize = _ftelli64(fh);
	fseek_err = _fseeki64(fh, 0, SEEK_SET); assert(fseek_err == 0);
	printf("\nFile Size: %I64u\n", fileSize);

	// Read the buffer full
	//	Save the position before the read as we will need to rewind to this position before our write
	while ((read = ReadForUpdate(buff, 1, sizeof(buff), fh, &fpos)) > 0)
	{
		// see if there is anything to write
		if (read > 0)
		{
			if (fpos + read >= fileSize)
			{
				if (mode != IO_TEST)
					printf("last block, finishing up...\n");
			}

			switch (mode)
			{
			case ENCRYPT:
			{
				uint16_t new_size;
				uint8_t is_lastblock = (fpos + read >= fileSize);
				// pad the data to block size
				new_size = GUTL_PadBlockRaw(buff, (uint16_t)read, is_lastblock);
				GKO_Encrypt(&state, buff, (uint16_t)new_size);
				read = new_size;
			}
			break;
			case DECRYPT:
				GKO_Decrypt(&state, buff, (uint16_t)read);
				if (fpos + read >= fileSize)
				{	// if we are on the last block, unpad it and shrink the file
					long delta = (long)read;
					read = GUTL_UnPadBlockRaw(buff, (uint16_t)read);
					delta -= (long)read;
					// shorten the file by padbytes amount
					_chsize(_fileno(fh), (long)fileSize - delta); assert(errno == 0);
					fflush(fh); assert(errno == 0);
				}
				break;
			case IO_TEST:
				; // do nothing 
				break;
			}

			/* write the encrypted data */
			WriteForUpdate(buff, 1, (size_t)read, fh, &fpos);

			if ((_ftelli64(fh) % 0xFFFF) == 0)
				printf("File position: %I64u\n", _ftelli64(fh));
		}
		else
			return;
	}

	return;
}

