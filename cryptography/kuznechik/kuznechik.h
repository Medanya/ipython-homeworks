#ifndef KUZNECHIK_H
#define KUZNECHIK_H
#include <stdint.h>

// union fpr 128 bit datatype
typedef union {	
    uint64_t half[2];
    uint8_t  one_sixt[16];
} w128_t;
 
 //structure for all 10 keys
typedef struct {
	w128_t k[10];		// round keys
} kuz_key_t;

// init lookup tables
void init_tables();

// key setup
void set_encrypt_key(kuz_key_t *subkeys, const uint8_t key[32]);	
void set_decrypt_key(kuz_key_t *subkeys, const uint8_t key[32]);	

// single-block ecp ops
void encrypt_block(kuz_key_t *subkeys, void *x);
void decrypt_block(kuz_key_t *subkeys, void *x);

#endif
