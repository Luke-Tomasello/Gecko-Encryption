#include "stdint.h"

const uint8_t Perrault[3644] = {	// strlen + 16
"Little Red Riding Hood\n"
"Charles Perrault\n"
"Once upon a time there lived in a certain village a little country girl, the prettiest creature who was ever seen. Her mother was excessively fond of her; and her grandmother doted on her still more. This good woman had a little red riding hood made for her. It suited the girl so extremely well that everybody called her Little Red Riding Hood.\n"
"One day her mother, having made some cakes, said to her, \"Go, my dear, and see how your grandmother is doing, for I hear she has been very ill. Take her a cake, and this little pot of butter.\"\n"
"\n"
"Little Red Riding Hood set out immediately to go to her grandmother, who lived in another village.\n"
"As she was going through the wood, she met with a wolf, who had a very great mind to eat her up, but he dared not, because of some woodcutters working nearby in the forest. He asked her where she was going. The poor child, who did not know that it was dangerous to stay and talk to a wolf, said to him, \"I am going to see my grandmother and carry her a cake and a little pot of butter from my mother.\"\n"
"\"Does she live far off?\" said the wolf\n"
"\"Oh I say,\" answered Little Red Riding Hood; \"it is beyond that mill you see there, at the first house in the village.\"\n"
"\"Well,\" said the wolf, \"and I'll go and see her too. I'll go this way and go you that, and we shall see who will be there first.\"\n"
"\n"
"The wolf ran as fast as he could, taking the shortest path, and the little girl took a roundabout way, entertaining herself by gathering nuts, running after butterflies, and gathering bouquets of little flowers. It was not long before the wolf arrived at the old woman's house. He knocked at the door: tap, tap.\n"
"\"Who's there?\"\n"
"\"Your grandchild, Little Red Riding Hood,\" replied the wolf, counterfeiting her voice; \"who has brought you a cake and a little pot of butter sent you by mother.\"\n"
"The good grandmother, who was in bed, because she was somewhat ill, cried out, \"Pull the bobbin, and the latch will go up.\"\n"
"The wolf pulled the bobbin, and the door opened, and then he immediately fell upon the good woman and ate her up in a moment, for it been more than three days since he had eaten. He then shut the door and got into the grandmother's bed, expecting Little Red Riding Hood, who came some time afterwards and knocked at the door: tap, tap.\n"
"\"Who's there?\"\n"
"Little Red Riding Hood, hearing the big voice of the wolf, was at first afraid; but believing her grandmother had a cold and was hoarse, answered, \"It is your grandchild Little Red Riding Hood, who has brought you a cake and a little pot of butter mother sends you.\"\n"
"The wolf cried out to her, softening his voice as much as he could, \"Pull the bobbin, and the latch will go up.\"\n"
"Little Red Riding Hood pulled the bobbin, and the door opened.\n"
"The wolf, seeing her come in, said to her, hiding himself under the bedclothes, \"Put the cake and the little pot of butter upon the stool, and come get into bed with me.\"\n"
"Little Red Riding Hood took off her clothes and got into bed. She was greatly amazed to see how her grandmother looked in her nightclothes, and said to her, \"Grandmother, what big arms you have!\"\n"
"\"All the better to hug you with, my dear.\"\n"
"\"Grandmother, what big legs you have!\"\n"
"\"All the better to run with, my child.\"\n"
"\"Grandmother, what big ears you have!\"\n"
"\"All the better to hear with, my child.\"\n"
"\"Grandmother, what big eyes you have!\"\n"
"\"All the better to see with, my child.\"\n"
"\"Grandmother, what big teeth you have got!\"\n"
"\"All the better to eat you up with.\"\n"
"\n"
"And, saying these words, this wicked wolf fell upon Little Red Riding Hood, and ate her all up."};
const uint8_t TheTruth[122] = {	// strlen + 16
"The truth is incontrovertible."
" Malice may attack it,"
" ignorance may deride it,"
" but in the end, there it is." };
const uint8_t LoremIpsum[443]= {		// strlen + 16
"Posuere lorem Ipsum\n"
"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Adipiscing commodo elit at imperdiet dui accumsan sit. Ipsum dolor sit amet consectetur adipiscing elit.\n"
"Vivamus laoreet\n"
"Auctor augue mauris augue neque. Posuere lorem ipsum dolor sit amet consectetur adipiscing.\n"
"Porta non pulvinar neque laoreet. Viverra ipsum nunc aliquet bibendum."};
const uint8_t Kipling[1497]={			// strlen + 16
"If by Rudyard Kipling\n"
"If you can keep your head when all about you\n"
"Are losing theirs and blaming it on you;\n\n"
"If you can trust yourself when all men doubt you,\n"
"But make allowance for their doubting too;\n"
"If you can wait and not be tired by waiting,\n"
"Or, being lied about, don't deal in lies,\n"
"Or, being hated, don't give way to hating,\n"
"And yet don't look too good, nor talk too wise;\n"
"If you can dream-and not make dreams your master;\n"
"If you can think-and not make thoughts your aim;\n"
"If you can meet with triumph and disaster\n"
"And treat those two impostors just the same;\n"
"If you can bear to hear the truth you've spoken\n"
"Twisted by knaves to make a trap for fools,\n"
"Or watch the things you gave your life to broken,\n"
"And stoop and build 'em up with wornout tools;\n"
"\n"
"If you can make one heap of all your winnings\n"
"And risk it on one turn of pitch-and-toss,\n"
"And lose, and start again at your beginnings\n"
"And never breathe a word about your loss;\n"
"If you can force your heart and nerve and sinew\n"
"To serve your turn long after they are gone,\n"
"And so hold on when there is nothing in you\n"
"Except the Will which says to them: \"Hold on\";\n"
"\n"
"If you can talk with crowds and keep your virtue,\n"
"Or walk with kings-nor lose the common touch;\n"
"If neither foes nor loving friends can hurt you;\n"
"If all men count with you, but none too much;\n"
"If you can fill the unforgiving minute\n"
"With sixty seconds' worth of distance run-\n"
"Yours is the Earth and everything that's in it,\n"
"And-which is more-you'll be a Man, my son!"};


// Gecko keys and IV
#if defined(_GKO256)
const uint8_t gko_key[] = {	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 
								0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
//const int GKO_key256Nelts = (sizeof(GKO_key256) / sizeof(GKO_key256[0]));
#elif defined(_GKO192)
const uint8_t gko_key[] = {	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
								0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
//const int GKO_key192Nelts = (sizeof(GKO_key192) / sizeof(GKO_key192[0]));
#elif defined(_GKO128)
const uint8_t gko_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
//const int GKO_key128Nelts = (sizeof(GKO_key128) / sizeof(GKO_key128[0]));
#endif

const uint8_t gko_iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

// AES keys and IV
#if defined(AES256)
uint8_t aes_key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
#elif defined(AES192)
uint8_t aes_key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
#elif defined(AES128)
uint8_t aes_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif

uint8_t aes_iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
