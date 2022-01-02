


#include     <stdio.h>
#include  "WLcrypto.h"    //#include  "WLaes256.h"  

//  After encryption, the string length increases by 4 bytes. These 4 bytes store the number of characters
//  of the string before encryption. These 4 bytes are at the beginning of the encrypted string (in plaintext).

char szWords[17][120] = {                      
                  "https://github.com/ilvn",                                      //  We will encrypt these lines with                               
                    "Tiny C Compiler (TCC)",                                      //  the default encryption key.
                   "Tested by GCC and TCC compilers", 
  "All the code in this example is written in C",
  "Byte-oriented AES-256 implementation.",							      
  "All lookup tables replaced with 'on the fly' calculations.",             
  "Copyright (c) 2007 Ilya O. Levin, http://www.literatecode.com", 
  "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -",           //  And starting from this line, we will 
            "E-mail: dllbridge@gmail.com",                                  //  change one byte in the encryption key.
                       "2021 December 29",
							      "14:14",  
						 "Dmitry Sobolev",
  "This demo example and interface functions for working with strings made:",
  "All the lines printed below have been restored after decryption:" };




////////////////////////////////////////////////////////////
int main ()                                               //               
{

	int        res = 0,
	             i = 0;

	unsigned char *psZ;
	
	printf("We print the length of the encrypted strings separated by commas:\n");
	for(i = 0; i < 14; i++)
	{                                                                    
		if(i == 7) { key[4] = 81;  aes256_init(&ctx, key); }      //  We change one (4th) byte in the encryption key.
		                                                  //  Starting from the 7th line, the encryption key changes.		                                                                       		
	    res = WL_encAES256(szWords[i]);
	    printf("%d, ", res);                  //  We print, separated by commas, the length of the encrypted strings.
    }   printf("\n");

	for(i = 13; i > -1; i--)                             // In reverse order to change the encryption key less often.
	{
	   
	    WL_AES256dec(szWords[i]);
	    printf("%s\n", &szWords[i]);
	                                                                             // Try commenting out the line below.
	    if(i == 7) { key[4] = 4; aes256_init(&ctx, key); } // We change the encryption key back. As it was by default.
    }                                                        
    
    
    printf("\n - - - - - - -       SHA-256 testing:\n");

	
	psZ = WL_sha256(    "abc", 3);  dump1("    abc: ", psZ, 32);
    psZ = WL_sha256("1234567", 7);  dump1("1234567: ", psZ, 32);
    psZ = WL_sha256(    "777", 3);  dump1("    777: ", psZ, 32);

return 0;
}
















/*

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//             2)    Demo AES-256 by Ilya O. Levin                   |
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +



//  
//   Byte-oriented AES-256 implementation.
//   All lookup tables replaced with 'on the fly' calculations. 
//
//  Copyright (c) 2007 Ilya O. Levin, http://www.literatecode.com
//
//  Permission to use, copy, modify, and distribute this software for any
//  purpose with or without fee is hereby granted, provided that the above
//  copyright notice and this permission notice appear in all copies.
//
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include <stdlib.h>
#include <stdio.h>
#include "aes256.h"

#define DUMP(s, i, buf, sz)  {printf(s);                   \
                              for (i = 0; i < (sz);i++)    \
                                  printf("%02x ", buf[i]); \
                              printf("\n");}

int main (int argc, char *argv[])
{
    aes256_context ctx; 
    uint8_t key[32];
    uint8_t buf[16], i;

    // put a test vector 
    for (i = 0; i < sizeof(buf);i++) buf[i] = i * 16 + i;
    for (i = 0; i < sizeof(key);i++) key[i] = i;

    DUMP("txt: ", i, buf, sizeof(buf));
    DUMP("key: ", i, key, sizeof(key));
    printf("---\n");

    aes256_init(&ctx, key);
    aes256_encrypt_ecb(&ctx, buf);

    DUMP("enc: ", i, buf, sizeof(buf));
    printf("tst: 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89\n");

    aes256_init(&ctx, key);
    aes256_decrypt_ecb(&ctx, buf);
    DUMP("dec: ", i, buf, sizeof(buf));

    aes256_done(&ctx);

    return 0;
} 
*/






/*

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +                A toy encryption algorithm.
//             3)    Demo Zcipher by Ilya O. Levin                   |
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//
//  Zcipher. Test and Usage Sample
//  Written by Ilya O. Levin, http://www.literatecode.com
//


#pragma warning(push, 1)
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#pragma warning(pop)

#define uint32_t unsigned long

#define TEST_LOOPS 13107200

void cvsched(uint32_t *);
void encr   (uint32_t *);
void decr   (uint32_t *);

uint32_t k[6] = {0};

// ------------------------------------------------------------------------- /
int main(void)
{
    clock_t t;
    double dt;
    int i;

    printf("Zcipher Tests\n\n");

    printf("* Encrypting %3d Mb - ", (TEST_LOOPS * sizeof(k[0])*2)/1048576);
    t = clock();
    cvsched(k);
    for (i = 0, dt = 0; i < TEST_LOOPS; i++ ) encr(k);
    dt = (double)(clock() - t) / CLOCKS_PER_SEC;
    printf("%2.3f sec [%08x]\r\n", dt, (k[0] ^ k[1]));

    printf("  + key streaming -   ");
    t = clock();
    for (i = 0, dt = 0; i < TEST_LOOPS; i++ ) cvsched(k), encr(k);
    dt = (double)(clock() - t) / CLOCKS_PER_SEC;
    printf("%2.3f sec [%08x]\r\n", dt, (k[0] ^ k[1]));


    printf("\nKey Stream Generator:\n");

    k[2] = 0x11111111; k[3] = 0x22222222; k[4] = 0x33333333; k[5] = 0x44444444;

    printf("#0: %08x %08x %08x %08x\n", k[2], k[3], k[4], k[5]);
    cvsched(k);    
    printf("#1: %08x %08x %08x %08x - %s\n", k[2], k[3], k[4], k[5],
            ((k[2]==0x7a7db236) && (k[3]==0x8d69797c) && 
             (k[4]==0xea87711e) && (k[5]==0xe183da90)) ? "PASSED" : "FAILED"
            );
    cvsched(k);    
    printf("#2: %08x %08x %08x %08x - %s\n", k[2], k[3], k[4], k[5],
            ((k[2]==0xbd03c8dc) && (k[3]==0x98e5347f) && 
             (k[4]==0x8cfb9730) && (k[5]==0x45dc0cc9)) ? "PASSED" : "FAILED"
            );

    cvsched(k);    
    printf("#3: %08x %08x %08x %08x - %s\n", k[2], k[3], k[4], k[5],
            ((k[2]==0x96fbbf1d) && (k[3]==0x2f7d4382) && 
             (k[4]==0xc3fabc58) && (k[5]==0x42f34f4d)) ? "PASSED" : "FAILED"
            );


    printf("\nCodebook:\n");

    k[2] = 0x11111111; k[3] = 0x22222222; k[4] = 0x33333333; k[5] = 0x44444444;

    k[0] = 0x12345678; k[1] = 0x9abcdef0; 
             printf("* %08x %08x -> ", k[0], k[1]);
    encr(k); printf(  "%08x %08x -> ", k[0], k[1]);
    decr(k); printf(  "%08x %08x  \n", k[0], k[1]);

    k[0] = k[1] = 0; 
             printf("* %08x %08x -> ", k[0], k[1]);
    encr(k); printf(  "%08x %08x -> ", k[0], k[1]);
    decr(k); printf(  "%08x %08x  \n", k[0], k[1]);


    k[0] = k[1] = 0xFFFFFFFF; 
             printf("* %08x %08x -> ", k[0], k[1]);
    encr(k); printf(  "%08x %08x -> ", k[0], k[1]);
    decr(k); printf(  "%08x %08x  \n", k[0], k[1]);

return 0;
} 


*/








