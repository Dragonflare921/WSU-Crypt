// Brandon Warner
// @dragonflare921
// dragonflare921@gmail.com
//
// WSU-Crypt
//
// simple implementation of WSU-Crypt encryption algorithm
//
// based on the Twofish block cipher by Bruce Schneier,
// John Kelsey, Doug Witing, David Wagner, and Chris Hall
// and the SKIPJACK block cipher by the NSA
//
// uses 64 bit blocks and 64 bit keys
//
// wsu_crypt.h:
//  WSU-Crypt interface header file. provides prototypes
//  for WSU-Crypt functionality


// header guard
#ifndef _WC_CRYPT_H_
#define _WC_CRYPT_H_

#include "util.h"

// debug and error stuff
// error types
typedef enum WC_ERR {
  WC_OK,
  WC_BAD_KEY,
  WC_BAD_SRC_BLOCK,
  WC_BAD_DEST_BLOCK,
  WC_UNKNOWN
} WC_ERR;


// error helper functions
char* wcerr(WC_ERR errcode);  // returns a string representing an error code


// globals
// (i know this isnt safe but this is hw. never roll your own crypto in the wild)
unsigned char G_WC_KEY[KEY_SIZE];      // the current stored key
unsigned char FTABLE[16*16];  // skipjack style F-Table

// cipher helper functions
// puts F0 and F1 into fresults
WC_ERR wcF(unsigned short r0, unsigned short r1, unsigned int round, char mode, unsigned short* fresults);

// returns 16bit concatenation following substitution with ftable
unsigned short wcG(unsigned short w, unsigned int round, char mode, unsigned char* keys);

// returns a subkey based on the mode and the previous subkey (in G_WC_KEY)
unsigned char wcK(unsigned char x, char mode);

// main operations copy between buffers internally and return error codes
WC_ERR wcCipher(unsigned char* inbuff, unsigned char* outbuff, unsigned char* key, char mode);

#endif //_WC_CRYPT_H_
