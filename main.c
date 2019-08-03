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
// main.c:
//  driver for the WSU-Crypt cipher. handles arguments,
//  opens files, and performs appropriate operation
//  depending on the mode passed from the command line


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "util.h"
#include "wsu_crypt.h"


// help text
void printHelp() {
  printf("WSU-Crypt\n\n\
Brandon Warner\n\
@dragonflare921\n\
dragonflare921@gmail.com\n\
CS427, Spring 2019, Project 1\n\
WSU Vancouver\n\n\
Block cipher based on AES candidate \'Twofish\' and the NSA\'s \'SKIPJACK\'\n\n\n\
Usage:\n\
  ./wsucrypt [OPTIONS]\n\n\
Options:\n\
  -k <FNAME>     --key <FNAME>     Use given key file\n\
  -t <FNAME>     --text <FNAME>    Use given text file\n\
  -e [FNAME]     --encrypt [FNAME] Perform an encryption on the text file (optional output name)\n\
  -d [FNAME]     --decrypt [FNAME] Perform a decryption on the text file (optional output name)\n\
  -h             --help            Show this help text\n");
  
}

// parse arguments from cli
void parseArgs(int argc, char** argv, char* keypath, char* textpath, char* mode) {
  for (int i = 0; i < argc; i++) {
    // skip improperly formatted args
    if (argv[i][0] != '-') {
      continue;
    }
    
    // help
    if ((strcmp("-h", argv[i]) == 0) || (strcmp("--help", argv[i]) == 0)) {
      printHelp();
      exit(EXIT_SUCCESS);
    }
    
    // key file
    else if ((strcmp("-k", argv[i]) == 0) || (strcmp("--key", argv[i]) == 0)) {
    
      // cap filename length to avoid overflow
      int maxcpy = strlen(argv[i+1])+1;
      if (maxcpy > MAX_BUFF) {
#ifdef DEBUG
        printf("[DBUG]: tsk tsk");
#endif //DEBUG
        maxcpy = MAX_BUFF;
      }
      
      // copy new filename
      strncpy(keypath, argv[i+1], maxcpy);
      
      // bump i past the filename
      i++;
    }
    
    // plaintext file
    else if ((strcmp("-t", argv[i]) == 0) || (strcmp("--text", argv[i]) == 0)) {
      
      // cap filename length to avoid overflow
      int maxcpy = strlen(argv[i+1])+1;
      if (maxcpy > MAX_BUFF) {
#ifdef DEBUG
        printf("[DBUG]: tsk tsk");
#endif //DEBUG
        maxcpy = MAX_BUFF;
      }
      
      // copy new filename
      strncpy(textpath, argv[i+1], maxcpy);
      
      // bump i past the filename
      i++;
    }
    
    // encryption
    else if ((strcmp("-e", argv[i]) == 0) || (strcmp("--encrypt", argv[i]) == 0)) {
      *mode = 0;
    }
    
    // decryption
    else if ((strcmp("-d", argv[i]) == 0) || (strcmp("--decrypt", argv[i]) == 0)) {
      *mode = 1;
    }
  }
  
  return;
}

// entry point
int main(int argc, char** argv) {
  // too few args
  if (argc < 2) {
  
#ifdef DEBUG
  printf("[DBUG]: no args\n");
#endif //DEBUG

    printHelp();
    exit(EXIT_FAILURE);
  }
  
  // settings passed from command line
  // flags
  char mode = -1;    // 0 for encrypt, nonzero for decrypt, -1 used for parsing init check
  
  // cap the buffer size
  char keypath[MAX_BUFF];
  char textpath[MAX_BUFF];
  char cipherpath[MAX_BUFF];
  
  // default filenames for assignment
  strcpy(keypath, "key.txt");
  strcpy(textpath, "plaintext.txt");
  strcpy(cipherpath, "ciphertext.txt");
  
  // parse arguments into locals
  parseArgs(argc, argv, keypath, textpath, &mode);
  
  // if we didnt get a mode, error out
  if (mode == -1) {
    fprintf(stderr, "[ERR!]: failed to supply mode. use -e (--encrypt) or -d (--decrypt).\n");
    exit(EXIT_FAILURE);
  }
  
#ifdef DEBUG
  printf("[DBUG]: parsed args:\n key = %s\n text = %s\n mode = %s\n", keypath, textpath, mode?"decrypt":"encrypt");
#endif //DEBUG
  
  // open the files from disk
  FILE* keyfile = fopen(keypath, "r");
  FILE* plainfile;
  FILE* cipherfile;
  
  // information derived from the file
  unsigned int textlen;
  unsigned int blockcount;
  
  // holds error codes
  int e;
  
  // TODO (Dragon): could save memory and just use the big buffers for str and bytes
  //       bytes in first half of buffer after conversion
  //       just replace character pairs with 0 and "append" the byte to first half till you hit the end
  //
  //       not really necessary at all here but just a thought
  
  // buffers for the block and key
  unsigned char bstr[2*BLOCK_SIZE+1];   // holds the block's hex string chars before/after conversion to/from bytes
  unsigned char kstr[2*KEY_SIZE+1];     // holds the key's hex string chars before conversion to bytes
  unsigned char pblock[BLOCK_SIZE];     // holds the bytes for the plaintext block
  unsigned char cblock[BLOCK_SIZE];     // holds the bytes for the ciphertext block
  unsigned char key[KEY_SIZE];          // holds the bytes for the key
  
  
  // do the operation
  if (!mode) {  // ENCRYPTION
    plainfile = fopen(textpath, "r");
    cipherfile = fopen(cipherpath, "w");
    
    // get the size of the input file
    fseek(plainfile, 0, SEEK_END);
    textlen = ftell(plainfile);
    fseek(plainfile, 0, SEEK_SET);
    
    // find out how many blocks to encrypt (round up)
    blockcount = ceil((textlen/2)/BLOCK_SIZE);
    
    // process every block and write it to the ciphertext file
    for (int i = 0; i < blockcount; i++) {
      
      // read the hex strings from given files
      fread(bstr, 1, 2*BLOCK_SIZE, plainfile);
      fread(kstr, 1, 2*KEY_SIZE, keyfile);
      
      // convert input (plaintext) hex string to byte array
      if ((e = hexstr_bytes(bstr, pblock, BLOCK_SIZE)) != U_OK) {
        fprintf(stderr, "[ERR!]: hexstr_bytes returned error code: %d, %s\n", e, utilerr(e));
        exit(EXIT_FAILURE);
      }
      
      // clear out the string for temp storage
      memset(bstr, 0, 2*BLOCK_SIZE+1);
      
      // convert key hex string to byte array
      if ((e = hexstr_bytes(kstr, key, KEY_SIZE)) != U_OK) {
        fprintf(stderr, "[ERR!]: hexstr_bytes returned error code: %d, %s\n", e, utilerr(e));
        exit(EXIT_FAILURE);
      }
      
      // pass the cblock as an arg to do a clean copy inside WSU-Crypt
      // wcEncrypt returns error codes, check for errors here
      if ((e = wcCipher(pblock, cblock, key, 'e')) != WC_OK) {
        fprintf(stderr, "[ERR!]: wcEncrypt returned error code: %d, %s\n", e, wcerr(e));
        exit(EXIT_FAILURE);
      }
      
      // convert output (ciphertext) byte array to hex string
      if ((e = bytes_hexstr(cblock, bstr, BLOCK_SIZE)) != U_OK) {
        fprintf(stderr, "[ERR!]: bytes_hexstr returned error code: %d, %s\n", e, utilerr(e));
        exit(EXIT_FAILURE);
      }
      
      // write the new ciphertext block to the generated ciphertext file
      fwrite(bstr, 1, 2*BLOCK_SIZE, cipherfile);
#ifdef DEBUG
      printf("[DBUG]: wrote %s\n", bstr);
#endif //DEBUG
    }
  }
  else {    // DECRYPTION
    cipherfile = fopen(cipherpath, "r");
    plainfile = fopen(textpath, "w");
    
    // get the size of the input file
    fseek(cipherfile, 0, SEEK_END);
    textlen = ftell(cipherfile);
    fseek(cipherfile, 0, SEEK_SET);
    
    // find out how many blocks to decrypt (round up)
    blockcount = ceil((textlen/2)/BLOCK_SIZE);
    
    // process every block and write it to the plaintext file
    for (int i = 0; i < blockcount; i++) {

      // read the hex strings from given files
      fread(bstr, 1, 2*BLOCK_SIZE, cipherfile);
      fread(kstr, 1, 2*KEY_SIZE, keyfile);
      
      // convert input (ciphertext) hex string to byte array
      if ((e = hexstr_bytes(bstr, cblock, BLOCK_SIZE)) != U_OK) {
        fprintf(stderr, "[ERR!]: hexstr_bytes returned error code: %d, %s\n", e, utilerr(e));
        exit(EXIT_FAILURE);
      }
      
      // clear out the string for temp storage
      memset(bstr, 0, 2*BLOCK_SIZE+1);
      
      // convert key hex string to byte array
      if ((e = hexstr_bytes(kstr, key, KEY_SIZE)) != U_OK) {
        fprintf(stderr, "[ERR!]: hexstr_bytes returned error code: %d, %s\n", e, utilerr(e));
        exit(EXIT_FAILURE);
      }
      
      // pass the pblock as an arg to do a clean memcpy inside WSU-Crypt
      // wcDecrypt returns error codes, check for errors here
      if ((e = wcCipher(cblock, pblock, key, 'd')) != WC_OK) {
        fprintf(stderr, "[ERR!]: wcDecrypt returned error code: %d, %s\n", e, wcerr(e));
        exit(EXIT_FAILURE);
      }
      
      // convert output (plaintext) byte array to hex string
      if ((e = bytes_hexstr(pblock, bstr, BLOCK_SIZE)) != U_OK) {
        fprintf(stderr, "[ERR!]: bytes_hexstr returned error code: %d, %s\n", e, utilerr(e));
        exit(EXIT_FAILURE);
      }
      
      // write the new plaintext block to the generated ciphertext file
      fwrite(bstr, 1, 2*BLOCK_SIZE, plainfile);
#ifdef DEBUG
      printf("[DBUG]: wrote %s\n", bstr);
#endif //DEBUG
    }
  }
  
  // clean up
  fclose(keyfile);
  fclose(plainfile);
  fclose(cipherfile);
  
  // back to OS
  return 0;
}