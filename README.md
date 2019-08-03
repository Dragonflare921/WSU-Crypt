WSU-Crypt
=========

Implementation of WSU-Crypt encryption algorithm in C.

Based on the Twofish block cipher by Bruce Schneier, John Kelsey, Doug Witing, David Wagner, and Chris Hall, and the SKIPJACK block cipher by the NSA.

Uses 64 bit blocks and 64 bit keys


## Contents:
  - <span>util.c</span>: implementation of utility functions
  - <span>util.h</span>: utlity declarations for general helper functions
  - <span>wsu_crypt.c</span>: implementation of the WSU-Crypt interface
  - <span>wsu_crypt.h</span>: WSU-Crypt interface
  - <span>main.c</span>: driver for the WSU-Crypt cipher
  - <span>README.md</span>: this file
  - <span>Makefile</span>: build instructions for make

## Building:
```
  $ make
```
  
## Usage:
```
  $ ./wsucrypt -h
```

## Notes:
  The optional file name for output is unimplemented, and optional input for decryption is broken, but the optional filename for key should work for both decryption and encryption.