#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>
#include <string.h>
#include <openssl/sha.h>

#define BATCH_SIZE 4000
#define TX_SIZE 12
#define TX_DEFAULT "AAAAAAAAAAAA"

void initialize_data_structure(element_t x, pairing_t pairing, char *type);
void generate_private_public_keys(element_t g, element_t *secret_key, element_t *public_key);
void calculate_signatures(element_t h, element_t *secret_key, element_t *sig);
void aggregate_signatures(element_t agg_sig, element_t *sig);

/**
 * n = 4000
 * n secret key / public key pairs
 * a single transaction
 * this single transaction is signed by n signers, producing n unique signatures
 */


int main(void) {
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) {
        pbc_die("input error");
    }
    pairing_init_set_buf(pairing, param, count);

    // debug
    printf("%s\n", param);

    // holding system parameters
    element_t g, h;
    element_t *secret_key;
    element_t *public_key;
    element_t *sig;
    element_t temp1, temp2;
    element_t agg_sig;

    

    initialize_data_structure(g, pairing, "G2");
    
    // Only a single message being signed multiple times by different parties
    initialize_data_structure(h, pairing, "G1");
    
    initialize_data_structure(temp1, pairing, "GT");
    initialize_data_structure(temp2, pairing, "GT");
    
    // Allocate memory for secret_key, public_key and signature arrays
    secret_key = (element_t *)malloc(BATCH_SIZE * sizeof(element_t));
    public_key = (element_t *)malloc(BATCH_SIZE * sizeof(element_t));
    sig = (element_t *)malloc(BATCH_SIZE * sizeof(element_t));

    for (int i = 0; i < BATCH_SIZE; i++)
    {
        initialize_data_structure(public_key[i], pairing, "G2");
        initialize_data_structure(sig[i], pairing, "G1");
        initialize_data_structure(secret_key[i], pairing, "Zr");
    }
    
    element_random(g);

    generate_private_public_keys(g, secret_key, public_key);

    /*
    To implement, BLS Signature hashing
    */

    // const char *message = "Hello World";

    // Message Operations

    char *msg = (char *)malloc((TX_SIZE+1) * sizeof(char));

    if (msg == NULL) {
        fprintf(stderr, "Memory Allocation Fail");
        return 1;
    }

    snprintf(msg, TX_SIZE+1, TX_DEFAULT);

    printf("Msg: %s\n", msg);

    // SHA256 Hash the message

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char *)msg, TX_SIZE, hash);

    // Debug
    printf("SHA-256 hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");


    element_from_hash(h, hash, SHA256_DIGEST_LENGTH);

    calculate_signatures(h, secret_key, sig);

    // Aggregate signatures
    aggregate_signatures(agg_sig, sig);


    // Do pairings

    pairing_apply(temp1, sig, g, pairing);
    pairing_apply(temp2, h, public_key, pairing);

    // compare pairings

    if (!element_cmp(temp1, temp2)) {
        printf("Signature Verifies\n");
    } else {
        printf("Signature does not verify\n");
    }

    element_clear(g);
    element_clear(h);

    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        element_clear(secret_key[i]);
        element_clear(public_key[i]);
        element_clear(sig[i]);
    }
    free(secret_key);
    free(public_key);
    free(sig);

    element_clear(temp1);
    element_clear(temp2);

    free(msg);

    pairing_clear(pairing);

}

void initialize_data_structure(element_t x, pairing_t pairing, char *type) {
     if (strcmp(type, "G1") == 0) {
        element_init_G1(x, pairing);
    } else if (strcmp(type, "G2") == 0) {
        element_init_G2(x, pairing);
    } else if (strcmp(type, "GT") == 0) {
        element_init_GT(x, pairing);
    } else if (strcmp(type, "Zr") == 0) {
        element_init_Zr(x, pairing);
    }
}

void generate_private_public_keys(element_t g, element_t *secret_key, element_t *public_key) {
    for (int i = 0; i < BATCH_SIZE; i++)
    {
        element_random(secret_key[i]);

        element_pow_zn(public_key[i], g, secret_key[i]);
    }
    
}

void calculate_signatures(element_t h, element_t *secret_key, element_t *sig) {
    for (int i = 0; i < BATCH_SIZE; i++)
    {
        element_pow_zn(sig[i], h, secret_key[i]);
    }
    
}

void aggregate_signatures(element_t agg_sig, element_t *sig) {
    element_set1(agg_sig);
    for (int i = 0; i < BATCH_SIZE; i++) {
        element_mul(agg_sig, agg_sig, sig[i]);
    }
}
