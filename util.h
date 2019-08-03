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
// util.h:
//  utlity declarations for general helper functions


// header guard
#ifndef _UTIL_H_
#define _UTIL_H_

// globals
// maximum argument string buffer size
#define MAX_BUFF    512

// block and key size in bytes (64 bits)
#define BLOCK_SIZE  8
#define KEY_SIZE    8

// number of rounds during encryption and decryption
#define NUM_ROUNDS  16

// error types
typedef enum UTIL_ERR {
  U_OK,
  U_BAD_BUFFER,
  U_BAD_SIZE,
  U_BAD_CHAR,
  U_UNKNOWN
} UTIL_ERR;

// error helper functions
char* utilerr(UTIL_ERR errcode);  // returns a string representing an error code


// bit manipulation

// flip endianness of a 16bit short and return it
unsigned short bswap16(unsigned short in);

// bitwise rotate a byte array right
void rrotate(unsigned char* array, unsigned int size, unsigned int shift);

// bitwise rotate a byte array left
void lrotate(unsigned char* array, unsigned int size, unsigned int shift);

// return a 16bit short resulting from the concatenation of 2 bytes
unsigned short catbytes(unsigned char b1, unsigned char b2);

// format and return an index for the ftable
unsigned char ftable_index(unsigned char in);

// buffer conversion
// NOTE: size param represents the byte count for the *BYTE BUFFER*
//       regardless of the conversion, use the number of raw bytes
//       DO NOT PASS THE STRING BUFFER LENGTH

// convert from a hex string buffer of length 2*size to a byte buffer of length size
UTIL_ERR hexstr_bytes(unsigned char* strbuff, unsigned char* bytebuff, unsigned int size);

// convert from a byte buffer of length size to a hex string buffer of length 2*size
UTIL_ERR bytes_hexstr(unsigned char* bytebuff, unsigned char* strbuff, unsigned int size);

#endif //_UTIL_H_