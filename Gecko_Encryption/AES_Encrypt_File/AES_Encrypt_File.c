#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <io.h>
#include <malloc.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <direct.h>
#include <assert.h> 
#include "stdint.h"
#include "aes.h"


typedef enum Operations {ENCRYPT,DECRYPT,IO_TEST} Mode;

char _buff[512];
static size_t AES_Encrypt(char* buff, int len, uint8_t key[], uint8_t iv[]);
static size_t AES_Decrypt(char* buff, int len, uint8_t key[], uint8_t iv[]);
uint16_t static HELPER_UnPadBlockRaw(uint8_t* bp, uint16_t len);
uint16_t static HELPER_PadBlockRaw(uint8_t* bp, uint16_t len);

// TEST: create a temp key
#if defined(AES256)
uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
uint8_t out[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
#elif defined(AES192)
uint8_t key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
uint8_t out[] = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
#elif defined(AES128)
uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif
uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

void DoMainOperation(FILE* fh, char* buff, Mode mode);
int _cdecl _tmain(int argc, char* argv[])
{
	// int fh;
	FILE *fh; errno_t err;
	enum Mode mode;

	// test command line format
	if (argc  < 3)
	{
		printf("Usage: Gecko [-d|-e] filename\n");
		return 1;
	}

	// get the command args
	if  (!strcmp((const char *)argv[1], "-e"))
	{
		mode = ENCRYPT;
	}
	else if (!strcmp((const char *)argv[1], "-d"))
	{
		mode = DECRYPT;
	}
	else if (!strcmp((const char *)argv[1], "-io"))
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
	if( _access( argv[2], 0 ) == 0 ) {
		// file exists
	} else {
		// file doesn't exist
		printf("File %s not found.\n", argv[2]);
		return -1;
	}

	// optimization 2: buffered i/o is much better
	//	saves 1.085 seconds, or a 11.531512381762% speedup (IO_TEST)
	// 8.324000 is a 11.531512381762% decrease of 9.409000.
	err = fopen_s(&fh, argv[2], "r+bR");
	if( err != 0 )
		printf( "Open failed on file: %s\n", argv[2]);
	else
	{
		// give some status
		printf( "Open succeeded on file: %s\n", argv[2]);
		if  (mode == ENCRYPT) printf("Encrypting..."); 
		if (mode == DECRYPT) printf("Decrypting..."); 

		if (mode == IO_TEST)
		{
			int kx;
			clock_t start, end;
			double cpu_time_used;

			printf("Running I/O Test (buffered i/o) ..."); 
			start = clock();
			for (kx=0; kx < 128; kx++)
			{
				rewind(fh);							// go to the beginning of the file
				DoMainOperation(fh, _buff, mode);	// do it
			}
			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			printf("\nloop (I/O, 128) took %f seconds to execute\n", cpu_time_used); 
			return;
		}
		else
		{
			clock_t start, end;
			double cpu_time_used;
			start = clock();
			DoMainOperation(fh, _buff, mode);
			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			printf("\n%s took %f seconds to execute\n", (mode == ENCRYPT) ? "encryption" : (mode == DECRYPT) ? "decryption" : "task" ,cpu_time_used); 
		}

		printf( "Done.\n");
		// and cleanup
		fclose(fh);
	}

	return 0;
}
size_t ReadForUpdate(void *buffer, size_t size, size_t count, FILE *stream, fpos_t *pos)
{
	int fgetpos_err = fgetpos(stream,pos); assert(fgetpos_err == 0);
	if (fgetpos_err != 0) return 0;
	return fread(buffer, size, count, stream);
}


size_t WriteForUpdate(void *buffer, size_t size, size_t count, FILE *stream, fpos_t *pos)
{
	size_t count_written=0;
	int fsetpos_err;
	int fgetpos_err;

	// rewind to the position to before the read
	fsetpos_err = fsetpos(stream,pos); assert(fsetpos_err == 0);

	// write the data
	count_written = fwrite(buffer, size, count, stream);

	// get the current position
	// Microsoft docs
	// When the "r+", "w+", or "a+" access type is specified, both reading and writing are allowed (the file is said to be open for "update"). 
	// However, when you switch between reading and writing, there must be an intervening fflush, fsetpos, fseek, or rewind operation. 
	// The current position can be specified for the fsetpos or fseek operation, if desired.
	fgetpos_err = fgetpos(stream,pos); 
	assert(fgetpos_err == 0);

	// set the new position
	fsetpos_err = fsetpos(stream,pos);
	assert(fsetpos_err == 0);

	return count_written;
}

void DoMainOperation(FILE* fh, char* buff, Mode mode)
{
	__int64 read;
	fpos_t fpos;
	int fseek_err;
	__int64 fileSize;
	//
	//
	//
	//
	//
	//
	//
	//
	//

	// determine file size so we do not need to rely upon feof()
	fseek_err = _fseeki64(fh, 0 , SEEK_END); assert(fseek_err == 0);
	fileSize = _ftelli64(fh);
	fseek_err = _fseeki64(fh, 0 , SEEK_SET); assert(fseek_err == 0);
	printf ("\nFile Size: %I64u\n",fileSize);

	// Read the buffer full
	//	Save the position before the read as we will need to rewind to this position before our write
	while ((read = ReadForUpdate(buff, 1, 512, fh, &fpos)) > 0)
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
				{	// if last block is divisible by 16, we will need a final padding block,
					//	otherwise, use normal padding if needed
					if (read % AES_BLOCKLEN == 0)
					{	
						if (fpos + read >= fileSize)
						{	// add PKCS#7 padding for final block
							// read+= because we need account for the 16 bytes previously read
							// we ADD to it the 16 bytes padding (as per standard.)
							read+=HELPER_PadBlockRaw(&buff[read], 0);
						}
					}
					else if (read % AES_BLOCKLEN != 0)
					{	// add PKCS#7 padding for partial block
						// read is now the 'new block size' post padding
						read=HELPER_PadBlockRaw(buff, (uint16_t)read);
					}

					// encrypt
					read = AES_Encrypt(buff, (int)read, key, iv);
				}
				break;
			case DECRYPT:
				// do decrypt
				read = AES_Decrypt(buff, (int)read, key, iv);
				if (fpos + read >= fileSize)
				{	// unpad last block
					long delta = (long)read;
					read = HELPER_UnPadBlockRaw(buff, (uint16_t)read);
					delta -= (long)read;
					// shorten the file by padbytes amount
					_chsize(_fileno(fh),(long)fileSize - delta); assert(errno == 0);
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
				printf ("File position: %I64u\n",_ftelli64(fh));
		}
		else	
			return;
	}

	return;
}

// https://crypto.stackexchange.com/questions/6399/implementing-pkcs7-padding-on-a-stream-of-unknown-length
uint16_t static HELPER_PadBlockRaw(uint8_t* bp, uint16_t len)
{	// we were called because the data is  < AES_BLOCKLEN bytes
	// We will add padding bytes, where each pad byte the the number of padding bytes added
	// We will use PKCS#7 padding, decribed in Section 10.3 of RSA PKCS#7.
	int padval=0;

	if (len % AES_BLOCKLEN != 0)
		padval = AES_BLOCKLEN - (len % AES_BLOCKLEN);
	else if (len == 0)
		padval = AES_BLOCKLEN;
	else
		padval = 0;

	memset(&bp[len], padval, padval);

	// return number of padding bytes added
	return len + padval;
}
uint16_t static HELPER_UnPadBlockRaw(uint8_t* bp, uint16_t len)
{	// remove PKCS#7 padding and return the new data size
	unsigned ix;

	// this value should be the last padding byte, it also describes how many padding bytes there are.
	uint8_t last_char = bp[len-1];

	// buffer not padded
	if (last_char > AES_BLOCKLEN || last_char == 0)
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

size_t  AES_Encrypt(char* buff, int len, uint8_t key[], uint8_t iv[])
{
	int jx=0;
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_encrypt_buffer(&ctx, buff, len);

	return len;
}

size_t  AES_Decrypt(char* buff, int len, uint8_t key[], uint8_t iv[])
{
	int jx=0;
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, buff, len);

	return len;
}

