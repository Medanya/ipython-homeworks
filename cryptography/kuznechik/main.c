#include <stdio.h>
#include <time.h>
#include "kuznechik.h"
#include "string.h"

const uint8_t test_key[32] = {
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF	
};
const uint8_t testvec_pt[16] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 
	0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
};
const uint8_t testvec_ct[16] = { 
	0x7F, 0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30, 
	0x5A, 0x46, 0x8D, 0x42, 0xB9, 0xD4, 0xED, 0xCD
};

// debug print state
void print_w128(w128_t *x)
{
	int i;
	for (i = 0; i < 16; i++)
		printf(" %02X", x->one_sixt[i]);
	printf("\n");
}

void self_test() 
{
	int i;
	w128_t x;
	kuz_key_t key;

	printf("Self-test:\n");
	init_tables();
			
	set_encrypt_key(&key, test_key);	
	for (i = 0; i < 10; i++) {	
		printf("K_%d\t=", i + 1);
		print_w128(&key.k[i]);
	}

	for (i = 0; i < 16; i++)
		x.one_sixt[i] = testvec_pt[i];
	printf("MSG TO BE ENCRYPT\t=");
	print_w128(&x);

	encrypt_block(&key, &x);

	printf("ENCRYPTED MSG\t=");
	print_w128(&x);

	for (i = 0; i < 16; i++) {
		if (testvec_ct[i] != x.one_sixt[i]) {
			fprintf(stderr, 
			
			"Encryption self-test failure.\n");
			return ;
		}
	}

	set_decrypt_key(&key, test_key);
	decrypt_block(&key, &x);

	printf("DECRYPTED MSG\t=");
	print_w128(&x);

	for (i = 0; i < 16; i++) {
		if (testvec_pt[i] != x.one_sixt[i]) {
			fprintf(stderr, "Decryption self-test failure.\n");
			return ;
		}
	}

	printf("Self-test OK!\n");
}

void speed_test()
{
	int i, j, n;
	kuz_key_t key;
	uint32_t buf[0x100];
	clock_t tim;

	for (i = 0; i < 0x100; i++)
		buf[i] = i;
	set_encrypt_key(&key, test_key);	

	for (n = 100, tim = 0; tim < 2 * CLOCKS_PER_SEC; n <<= 1) {
		tim = clock();
		for (j = 0; j < n; j++) {
			for (i = 0; i < 0x100; i += 4)
				encrypt_block(&key, &buf[i]);
		}
		tim = clock() - tim;
		printf("Encrypt: %.3f kB/s (n=%dkB,t=%.3fs)\r",
			((double) CLOCKS_PER_SEC * n) / ((double) tim), 
			n, ((double) tim) / ((double) CLOCKS_PER_SEC));
		fflush(stdout);
	}
	printf("\n");
	
	
	for (i = 0; i < 0x100; i++)
		buf[i] = i;
	set_decrypt_key(&key, test_key);	

	for (n = 100, tim = 0; tim < 2 * CLOCKS_PER_SEC; n <<= 1) {
		tim = clock();
		for (j = 0; j < n; j++) {
			for (i = 0; i < 0x100; i += 4)
				decrypt_block(&key, &buf[i]);
		}
		tim = clock() - tim;
		printf("Decrypt: %.3f kB/s (n=%dkB,t=%.3fs)\r",
			((double) CLOCKS_PER_SEC * n) / ((double) tim), 
			n, ((double) tim) / ((double) CLOCKS_PER_SEC));
		fflush(stdout);
	}
	printf("\n");
}


int main(int argc, char **argv)
{	
	if(strcmp(argv[1],"-test")==0)
	{
		self_test();
	} else if (strcmp(argv[1],"-speed")==0){
		speed_test();
	} else if (argv[0] == NULL) {
		printf("Type -speed for speed test and -test for self test.");
	}
	
	return 0;
}