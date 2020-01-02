// utils
unsigned int random_range(int range_max, int range_min);
int test(int ch);
double diff(double a, double b);
int gcd(int a, int b);
unsigned char rotateLeft(unsigned char val, int N);
double diff(double a, double b);
unsigned long hash(unsigned char* str);
int32_t fileSize(FILE* fp);
uint32_t strsize(const char* string);
static __inline void new_keyiv(uint8_t CryptoKey[GKO_KEY_NELTS], uint8_t CryptoIv[GKO_KEY_NELTS]);
int _call_sample(char ch);
void gt_RegressionTest();

//#define GKO_KEY GKO_key
#define MAKE_FILENAME(mode) strcat(strcat(strcat(file_name, (0) ? ".bin": ".bin"), \
	(0) ? ".bin" :".bin"),\
	((GKO_KEY_NELTS == 16) ? ".128" : (GKO_KEY_NELTS == 24) ? ".192" : ".256"));

// test wrappers
void gt_HelloWorldCBC(int test);
void gt_HelloWorldAES_CBCvsGKO_CBC(int test);
void gt_HelloWorldCBCSender(int test);

void gt_HelloWorldECB(int test);
void gt_HelloWorldAES_ECBvsGKO_ECB(int test);
void gt_HelloWorldECBSender(int test);

void gt_HelloWorldCTR(int test);
void gt_HelloWorldAES_CTRvsGKO_CTR(int test);
void gt_HelloWorldCTRSender(int test);

void gt_gva_SmallBlockTest(int test, int buff_size);
void gt_gva_MediumBlockTest(int test, int buff_size);
void gt_gva_BigBlockTest(int test, int buff_size);
void gt_gva_BigBlockTestRaw(int test, int buff_size);
void gt_ChainBlockTest(int test);
void gt_MultiSessionTest(int test);
void gt_BlockModeFileTest(int test, int buff_size);
void gt_BlockModeWriteExample(int test);
void gt_BlockModeReadExample(int test);
#ifndef _SIZE
void gt_HelloWorldPCBC(int test);
void gt_HelloWorldPCBCSender(int test);
void gt_HelloWorldCFB(int test);
void gt_HelloWorldCFBSender(int test);
void gt_HelloWorldOFB(int test);
void gt_HelloWorldOFBSender(int test);
#endif // _SIZE