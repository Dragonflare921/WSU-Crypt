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
// util.c:
//  implementation of utility functions


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "util.h"


// returns a string representing an error code
char* utilerr(UTIL_ERR errcode) {
  
  // default to unknown error
  char* estr = "UNKNOWN";
  
  switch (errcode) {
  case U_BAD_BUFFER:
    estr = "BAD_BUFFER";
    break;
  case U_BAD_SIZE:
    estr = "BAD_SIZE";
    break;
  case U_BAD_CHAR:
    estr = "BAD_CHAR";
    break;
  case U_UNKNOWN: // intentionally fall through to default
  default:
    break;
  }
  
  return estr;
}


// bit manipulation

// flip endianness of a 16bit short and return it
unsigned short bswap16(unsigned short in) {
  unsigned short ret = (in & 0x00FF) << 8;
  ret |= (in & 0xFF00) >> 8;
  return ret;
}

// bitwise rotate a byte array right
void rrotate(unsigned char* array, unsigned int size, unsigned int shift) {

  // store the original size
  unsigned int osize = size;
  
  // outer loop to do rotates by more than 1
  for (int i = 0; i < shift; i++) {
    
    // restore the original size
    size = osize;
    
    // carry bits from shifting
    unsigned char thisbit = 0;
    unsigned char nextbit = thisbit;
    
    // shift each byte and bring the carry forward
    for (int j = 0; j < size; j++) {
      thisbit = nextbit;
      nextbit = (array[j] & 1) << 7;
      array[j] >>= 1;
      array[j] |= thisbit;
    }
    
    // finish rotation
    array[0] |= nextbit;
  }
  
  return;
}

// bitwise rotate a byte array left
void lrotate(unsigned char* array, unsigned int size, unsigned int shift) {
  
  // store the original size
  unsigned int osize = size;
  
  // outer loop to do rotates by more than 1
  for (int i = 0; i < shift; i++) {
    
    // restore the original size
    size = osize;
    
    // carry bits from shifting
    unsigned char thisbit = 0;
    unsigned char nextbit = thisbit;
    
    // shift each byte and bring the carry forward
    for (int j = size-1; j >= 0; j--) {
      thisbit = nextbit;
      nextbit = (array[j] & 0x80) >> 7;
      array[j] <<= 1;
      array[j] |= thisbit;
    }
    
    // finish rotation
    array[osize-1] |= nextbit;
  }
  
  return;
}

// return a 16bit short resulting from the concatenation of 2 bytes
unsigned short catbytes(unsigned char b1, unsigned char b2) {
  return ((b1 << 8) | b2);
}

// format and return an index for the ftable
unsigned char ftable_index(unsigned char in) {
  unsigned char ret;
  ret = ((in & 0xF0) >> 4) * 0x10;  // row
  ret += (in & 0x0F);   // column
  
  return ret;
}

// byte array <---> hex string conversions
// NOTE: tried to make these as small and fast as possible for later reuse
//       since i hadn't writen these *very useful* util functions in C before
//       it's important to note these treat things as a raw byte array
//       theres no endianness or byte swapping or division into fields at all
//       the order it comes in from the string is the order it goes out

// convert from a hex string buffer of length 2*size to a byte buffer of length size
UTIL_ERR hexstr_bytes(unsigned char* strbuff, unsigned char* bytebuff, unsigned int size) {
  
  // TODO (Dragon): this comparison uses the block size since the block and key size are the same
  //       for the undergrad version of the WSU-Crypt spec (64 bits)
  //
  //       THIS IS NOT ACCURATE OR SAFE WHEN CONVERTING KEYS IF KEY_SIZE != BLOCK_SIZE
  
  // make sure our size is fine
  if (size < 1 || size > BLOCK_SIZE) {
    return U_BAD_SIZE;
  }
  
  // make sure the buffers are good
  if (strbuff == NULL) {
    return U_BAD_BUFFER;
  }
  if (bytebuff == NULL) {
    return U_BAD_BUFFER;
  }
  
  // take the string 2 characters at a time to make a byte
  for (int i = 0; i < size*2; i+=2) {
    
    // make a string for the byte
    char a[2] = {strbuff[i], strbuff[i+1]};
  
    // TODO (Dragon): make sure this is how strtol actually works
    // used to check errors after conversion
    char* e = "";
  
    // TODO (Dragon): get rid of this library call altogether and just do some math
    // make the final byte
    unsigned char b = strtol(a, &e, 16);
    
    // TODO (Dragon): make sure this is how strtol actually works
    // make sure the characters were valid
    if (*e != '\0') {
      return U_BAD_CHAR;
    }
    
    // copy it to the byte buffer
    bytebuff[i/2] = b;
  }
  
  return U_OK;
}

// convert from a byte buffer of length size to a hex string buffer of length 2*size
UTIL_ERR bytes_hexstr(unsigned char* bytebuff, unsigned char* strbuff, unsigned int size) {
  
  // TODO (Dragon): this comparison uses the block size since the block and key size are the same
  //       for the undergrad version of the WSU-Crypt spec (64 bits)
  //
  //       THIS IS NOT ACCURATE OR SAFE WHEN CONVERTING KEYS IF KEY_SIZE != BLOCK_SIZE
  
  // make sure our size is fine
  if (size < 1 || size > BLOCK_SIZE) {
    return U_BAD_SIZE;
  }
  
  // make sure the buffers are good
  if (strbuff == NULL) {
    return U_BAD_BUFFER;
  }
  if (bytebuff == NULL) {
    return U_BAD_BUFFER;
  }
  // string representation of all hex digits
  char* hexchars = "0123456789ABCDEF";
  
  // grab each byte and make it 2 characters
  for (int i = 0; i < size; i++) {
    // copy the current byte
    unsigned char b = bytebuff[i];
    
    // convert and copy it to the string buffer
    strbuff[i*2] = hexchars[(b & 0xF0) >> 4];
    strbuff[(i*2)+1] = hexchars[b & 0x0F];
  }
  
  return U_OK;
}