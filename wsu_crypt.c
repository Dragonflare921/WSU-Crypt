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
// wsu_crypt.c:
//  implementation of the WSU-Crypt interface declared in
//  wsu_crypt.h. operates as a block cipher using the
//  Feistel cipher structure, researched by Horst Feistel
//  at IBM in the 1970s during the Lucifer project


#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "util.h"
#include "wsu_crypt.h"


// returns a string representing an error code
char* wcerr(WC_ERR errcode) {
  
  // default to unknown error
  char* estr = "UNKNOWN";
  
  switch (errcode) {
  case WC_BAD_KEY:
    estr = "BAD_KEY";
    break;
  case WC_BAD_SRC_BLOCK:
    estr = "BAD_SRC_BLOCK";
    break;
  case WC_BAD_DEST_BLOCK:
    estr = "BAD_DEST_BLOCK";
  case WC_UNKNOWN: // intentionally fall through to default
  default:
    break;
  }
  
  return estr;
}

// cipher helper functions
// puts F0 and F1 into fresults
WC_ERR wcF(unsigned short r0, unsigned short r1, unsigned int round, char mode, unsigned short* fresults) {
  
  // F() locals
  unsigned short t0;
  unsigned short t1;
  unsigned short _f0;
  unsigned short _f1;
  unsigned char g1keys[4];
  unsigned char g2keys[4];
  unsigned char fkeys[4];
  
  // values used for K() depending on mode
  unsigned int kround;
  
  if (mode == 'e') {
    kround = round;
    g1keys[0] = wcK(4 * kround, mode);
    g1keys[1] = wcK(4 * kround + 1, mode);
    g1keys[2] = wcK(4 * kround + 2, mode);
    g1keys[3] = wcK(4 * kround + 3, mode);
    g2keys[0] = wcK(4 * kround, mode);
    g2keys[1] = wcK(4 * kround + 1, mode);
    g2keys[2] = wcK(4 * kround + 2, mode);
    g2keys[3] = wcK(4 * kround + 3, mode);
    fkeys[0] = wcK(4 * kround, mode);
    fkeys[1] = wcK(4 * kround + 1, mode);
    fkeys[2] = wcK(4 * kround + 2, mode);
    fkeys[3] = wcK(4 * kround + 3, mode);
  }
  else if (mode == 'd') {
    kround = NUM_ROUNDS - 1 - round;
    fkeys[3] = wcK(4 * kround + 3, mode);
    fkeys[2] = wcK(4 * kround + 2, mode);
    fkeys[1] = wcK(4 * kround + 1, mode);
    fkeys[0] = wcK(4 * kround, mode);
    g2keys[3] = wcK(4 * kround + 3, mode);
    g2keys[2] = wcK(4 * kround + 2, mode);
    g2keys[1] = wcK(4 * kround + 1, mode);
    g2keys[0] = wcK(4 * kround, mode);
    g1keys[3] = wcK(4 * kround + 3, mode);
    g1keys[2] = wcK(4 * kround + 2, mode);
    g1keys[1] = wcK(4 * kround + 1, mode);
    g1keys[0] = wcK(4 * kround, mode);
    
  }
  
  // get the T values
  t0 = wcG(r0, round, mode, g1keys);
  t1 = wcG(r1, round, mode, g2keys);
  
  // calculate the F values
  _f0 = catbytes(fkeys[0], fkeys[1]);
  
  _f1 = catbytes(fkeys[2], fkeys[3]);
  
  unsigned short f0 = (t0 + 2 * t1 + _f0) % 65536;
  unsigned short f1 = (2 * t0 + t1 + _f1) % 65536;
  
  // pack them together
  fresults[0] = f0;
  fresults[1] = f1;
  
#ifdef DEBUG_F_FUNC
  printf("[DBUG]: f results:\n t0: 0x%04X\n t1: 0x%04X\n f0: 0x%04X\n f1: 0x%04X\n", t0, t1, f0, f1);
#endif //DEBUG_F_FUNC
  
  return WC_OK;
}

// TODO (Dragon): maybe generate all keys beforehand and pass them in
//       but if it works generating on the fly, then go ahead and stick with it
// returns 16bit concatenation following substitution with ftable
unsigned short wcG(unsigned short w, unsigned int round, char mode, unsigned char* keys) {
  
  unsigned char g1 = (w & 0xFF00) >> 8;
  unsigned char g2 = w & 0x00FF;
  unsigned char g3 = FTABLE[ftable_index(g2 ^ keys[0])] ^ g1;
  unsigned char g4 = FTABLE[ftable_index(g3 ^ keys[1])] ^ g2;
  unsigned char g5 = FTABLE[ftable_index(g4 ^ keys[2])] ^ g3;
  unsigned char g6 = FTABLE[ftable_index(g5 ^ keys[3])] ^ g4;
  unsigned short ret = catbytes(g5, g6);
  
#ifdef DEBUG_G_FUNC
  printf("[DBUG]: round %d g results:\n g1: 0x%02X\n g2: 0x%02X\n g3: 0x%02X\n g4: 0x%02X\n g5: 0x%02X\n g6: 0x%02X\n ret: 0x%04X\n", round, g1, g2, g3, g4, g5, g6, ret);
#endif //DEBUG_G_FUNC
  
  return ret;
}

// returns a subkey based on the mode and the previous subkey (in G_WC_KEY)
unsigned char wcK(unsigned char x, char mode) {
  
  // return value
  unsigned char ret = 0;
  
  // keys for encrypting
  if (mode == 'e') {
    // rotate the key in place
    lrotate(G_WC_KEY, KEY_SIZE, 1);
    
    // get the return value K[x mod 8]
    ret = G_WC_KEY[x % KEY_SIZE];
  }
  
  // keys for decrypting
  else if (mode == 'd') {
    // get the return value K[x mod 8]
    ret = G_WC_KEY[x % KEY_SIZE];
    
    // rotate the key in place
    rrotate(G_WC_KEY, KEY_SIZE, 1);
  }
  
  else {
    fprintf(stderr, "[ERR!]: invalid mode \'%c\' for K(), exiting...\n", mode);
    exit(EXIT_FAILURE);
  }
  
#ifdef DEBUG_K_FUNC
  printf("[DBUG]: k results: %02X\n", ret);
#endif //DEBUG_K_FUNC
  
  return ret;
}


// main WSU-Crypt cipher function. does both encryption and decryption
// operates on byte arrays encrypts/decrypts inbuff and places result in outbuff using key
// NOTE: this is written with a hard assumption that the key and block
//       will be 64 bits in length, and variable lengths are not supported
WC_ERR wcCipher(unsigned char* inbuff, unsigned char* outbuff, unsigned char* key, char mode) {
    
  // make sure the buffers are good
  if (inbuff == NULL) {
    return WC_BAD_SRC_BLOCK;
  }
  if (outbuff == NULL) {
    return WC_BAD_DEST_BLOCK;
  }
  if (key == NULL) {
    return WC_BAD_KEY;
  }
  
#ifdef DEBUG
  if (mode == 'e') {
    printf("[DBUG]: encrypting...\n");
  }
  else if (mode == 'd') {
    printf("[DBUG]: decrypting...\n");
  }
#endif //DEBUG
  
  // store the key
  memcpy(G_WC_KEY, key, KEY_SIZE);
  
  // locals
  unsigned int round = 0;     // current round number
  unsigned short fresults[2]; // F0 and F1
  unsigned short rwords[4];   // the current round's R values
  unsigned short ywords[4];   // the y values used after 16 rounds
  
  // input "whitening"
  // splits block and key into 4 words 16 bits each
  // generating words with catbytes() is fast (shift w/ or)
  // if we wanted to shortcut and just memcpy everything we'd
  // have to byteswap every word to fix up the endian order
  
  // block's words
  unsigned short bwords[4] = {
    catbytes(inbuff[0], inbuff[1]),
    catbytes(inbuff[2], inbuff[3]),
    catbytes(inbuff[4], inbuff[5]),
    catbytes(inbuff[6], inbuff[7])
  };
  
  // key's words
  unsigned short kwords[4] = {
    catbytes(G_WC_KEY[0], G_WC_KEY[1]),
    catbytes(G_WC_KEY[2], G_WC_KEY[3]),
    catbytes(G_WC_KEY[4], G_WC_KEY[5]),
    catbytes(G_WC_KEY[6], G_WC_KEY[7])
  };
  
  // xor the words for R values
  unsigned short nextr[4] = {
                    bwords[0] ^ kwords[0],
                    bwords[1] ^ kwords[1],
                    bwords[2] ^ kwords[2],
                    bwords[3] ^ kwords[3]
  };
  
  // perform each of the 16 rounds
  for (; round < NUM_ROUNDS; round++) {

#ifdef DEBUG_ROUNDS
    printf("[DBUG]: round %d rwords:\n r0: 0x%04X\n r1: 0x%04X\n r2: 0x%04X\n r3: 0x%04X\n", round, nextr[0], nextr[1], nextr[2], nextr[3]);
#endif //DEBUG_ROUNDS
    // set this round's R values
    memcpy(rwords, nextr, BLOCK_SIZE);
    
    // get F0 and F1 from F()
    wcF(rwords[0], rwords[1], round, mode, fresults);
    
    // calculate R values for next round
    if (mode == 'e') {
      nextr[0] = (rwords[2] ^ fresults[0]);
      rrotate((unsigned char*)&nextr[0], 2, 1);  // rotate in place
      lrotate((unsigned char*)&rwords[3], 2, 1); // rotate in place
      nextr[1] = rwords[3] ^ fresults[1];
    }
    else if (mode == 'd') {
      lrotate((unsigned char*)&rwords[2], 2, 1);  // rotate in place
      nextr[0] = (rwords[2] ^ fresults[0]);
      
      nextr[1] = rwords[3] ^ fresults[1];
      rrotate((unsigned char*)&nextr[1], 2, 1); // rotate in place
    }
    
    nextr[2] = rwords[0];
    nextr[3] = rwords[1];
    
#ifdef DEBUG_ROUNDS
    printf("[DBUG]: round %d results:\n 0x%04X%04X%04X%04X\n", round, nextr[0], nextr[1], nextr[2], nextr[3]);
#endif //DEBUG_ROUNDS
  }
  
  // undo the swap
  ywords[0] = nextr[2];
  ywords[1] = nextr[3];
  ywords[2] = nextr[0];
  ywords[3] = nextr[1];
  
  // output "whitening"
  ywords[0] = ywords[0] ^ kwords[0];
  ywords[1] = ywords[1] ^ kwords[1];
  ywords[2] = ywords[2] ^ kwords[2];
  ywords[3] = ywords[3] ^ kwords[3];
  
#ifdef DEBUG_ROUNDS
    printf("[DBUG]: ciphertext:\n 0x%04X%04X%04X%04X\n", ywords[0], ywords[1], ywords[2], ywords[3]);
#endif //DEBUG_ROUNDS
  
  // need to flip endianness for each yword to do memcpy right
  // probably faster cleaner way but w/e, short on time
  ywords[0] = bswap16(ywords[0]);
  ywords[1] = bswap16(ywords[1]);
  ywords[2] = bswap16(ywords[2]);
  ywords[3] = bswap16(ywords[3]);
  
  // copy result into output buffer
  memcpy(outbuff, ywords, BLOCK_SIZE);
  
  // success
  return WC_OK;
}

// at the bottom so we dont have to scroll past it all the time
unsigned char FTABLE[] = {   // skipjack style F-Table
0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46
};