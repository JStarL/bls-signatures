#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/time.h>

#define BATCH_SIZE 4000
#define TX_SIZE 12
#define TX_DEFAULT "AAAAAAAAAAAA"

void initialize_data_structure(element_t x, pairing_t pairing, char *type);
void generate_private_public_keys(element_t g, element_t *secret_key, element_t *public_key);
void calculate_signatures(element_t h, element_t *secret_key, element_t *sig);
void aggregate_signatures(element_t agg_sig, element_t *sig);
void compute_rhs(element_t rhs, element_t temp1, element_t h, element_t *public_key, pairing_t pairing);


/**
 * n = 4000
 * n secret key / public key pairs
 * a single transaction
 * this single transaction is signed by n signers, producing n unique signatures
 */


int main(void) {
    
    // To time functions
    struct timeval start, end;
    long seconds, useconds;
    double elapsed;
    
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
    element_t lhs, rhs;
    
    // Initialization

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
    
    initialize_data_structure(agg_sig, pairing, "G1");
    initialize_data_structure(lhs, pairing, "GT");
    initialize_data_structure(rhs, pairing, "GT");

    // System Parameters and Key Generation
    // NOT to be timed, this happens on an individual's computer,
    // not as a part of the rollup

    element_random(g);

    generate_private_public_keys(g, secret_key, public_key);

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

    /**
     * 1) Time the calculation of BLS signatures
     */

    gettimeofday(&start, NULL);

    calculate_signatures(h, secret_key, sig);

    gettimeofday(&end, NULL);

    seconds  = end.tv_sec  - start.tv_sec;
    useconds = end.tv_usec - start.tv_usec;
    elapsed = seconds * 1e6 + useconds;

    printf("Elapsed Time: Calculated Signatures: %.0f microseconds\n", elapsed);

    // Aggregate signatures
    aggregate_signatures(agg_sig, sig);

    // printf("Aggregated Signatures\n");

    // Pairings

    // lhs
    pairing_apply(lhs, agg_sig, g, pairing);

    compute_rhs(rhs, temp1, h, public_key, pairing);    

    // printf("Computed rhs\n");

    // pairing_apply(temp2, h, public_key, pairing);

    // compare lhs and rhs

    if (!element_cmp(lhs, rhs)) {
        printf("Aggregate Signature Verifies\n");
    } else {
        printf("Aggregate Signature does not verify\n");
    }

    // Cleanup

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

void compute_rhs(element_t rhs, element_t temp1, element_t h, element_t *public_key, pairing_t pairing) {
    for (int i = 0; i < BATCH_SIZE; i++)
    {
        pairing_apply(temp1, h, public_key[i], pairing);
        element_mul(rhs, rhs, temp1);
    }   
}