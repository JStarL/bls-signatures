#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <sys/time.h>

#define BATCH_SIZE 4000
#define TX_SIZE 12
#define TX_DEFAULT "AAAAAAAAAAAA"

int bls_ops(char *hash, struct timeval *start, struct timeval *end);
void initialize_data_structure(element_t x, pairing_t pairing, char *type);
void generate_private_public_keys(element_t g, element_t *secret_key, element_t *public_key);
void calculate_signatures(element_t h, element_t *secret_key, element_t *sig);
void aggregate_signatures(element_t agg_sig, element_t *sig);
void compute_rhs(element_t rhs, element_t temp1, element_t h, element_t *public_key, pairing_t pairing);

int ecdsa_ops(unsigned char *hash, struct timeval *start, struct timeval *end);
int generate_random_seckey(unsigned char *seckey);

/**
 * n = 4000
 * n secret key / public key pairs
 * a single transaction
 * this single transaction is signed by n signers, producing n unique signatures
 */

int main(void) {
    
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
    
    // To time functions
    struct timeval start, end;

    // BLS ops

    int bls_return = bls_ops(hash, &start, &end);

    if (bls_return) return bls_return;
    
    // ECDSA ops

    int ecdsa_return = ecdsa_ops(hash, &start, &end);
    
    if (ecdsa_return) return ecdsa_return;

    // Cleanup

    free(msg);

    return 0;
}

int ecdsa_ops(unsigned char *hash, struct timeval *start, struct timeval *end) {

    long seconds, useconds;
    double ecdsa_sig;

    printf("\n||============ ECDSA Signature Tests ============||");


    // Initialize the secp256k1 context for signing and verification
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Generate three random private keys
    unsigned char seckeys[BATCH_SIZE][32];
    for (int i = 0; i < BATCH_SIZE; i++) {
        int ecdsa_gen_key_return = generate_random_seckey(seckeys[i]);
        if (ecdsa_gen_key_return) return ecdsa_gen_key_return;
    }

    // Generate the public keys from the private keys
    secp256k1_pubkey pubkeys[BATCH_SIZE];
    for (int i = 0; i < BATCH_SIZE; i++) {
        if (!secp256k1_ec_pubkey_create(ctx, &pubkeys[i], seckeys[i])) {
            printf("Failed to create public key for key %d\n", i + 1);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /**
     * 1) Calculation of ECDSA Signatures
     */

    gettimeofday(start, NULL);

    secp256k1_ecdsa_signature signatures[BATCH_SIZE];

    // Create the signatures
    for (int i = 0; i < BATCH_SIZE; i++) {
        if (!secp256k1_ecdsa_sign(ctx, &signatures[i], hash, seckeys[i], NULL, NULL)) {
            printf("Failed to sign message with key %d\n", i + 1);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    gettimeofday(end, NULL);

    seconds  = end->tv_sec  - start->tv_sec;
    useconds = end->tv_usec - start->tv_usec;
    ecdsa_sig = seconds * 1e6 + useconds;

    printf("Elapsed Time: Calculate ECDSA Signatures: %.0f microseconds\n", ecdsa_sig);


    return 0;
}

int bls_ops(char *hash, struct timeval *start, struct timeval *end) {

    printf("\n||============= BLS Signature Tests =============||");

    long seconds, useconds;
    double elapsed;
    
    double bls_aggregation, bls_verification, bls_total;
    
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

    element_from_hash(h, hash, SHA256_DIGEST_LENGTH);

    /**
     * 1) Time the calculation of BLS signatures
     * NOTE: This happens on the user end, not as a part of the rollup
     */

    gettimeofday(start, NULL);

    calculate_signatures(h, secret_key, sig);

    gettimeofday(end, NULL);

    seconds  = end->tv_sec  - start->tv_sec;
    useconds = end->tv_usec - start->tv_usec;
    elapsed = seconds * 1e6 + useconds;

    printf("Elapsed Time: Calculated BLS Signatures: %.0f microseconds\n", elapsed);

    /**
     * 2) Time the aggregation of BLS signatures
     */

    gettimeofday(start, NULL);

    aggregate_signatures(agg_sig, sig);

    gettimeofday(end, NULL);

    seconds  = end->tv_sec  - start->tv_sec;
    useconds = end->tv_usec - start->tv_usec;
    bls_aggregation = seconds * 1e6 + useconds;

    printf("Elapsed Time: Aggregated BLS Signatures: %.0f microseconds\n", bls_aggregation);

    /**
     * 3) Time the verification of BLS signatures
     */

    gettimeofday(start, NULL);

    // lhs
    pairing_apply(lhs, agg_sig, g, pairing);

    // rhs
    compute_rhs(rhs, temp1, h, public_key, pairing);    

    // pairing_apply(temp2, h, public_key, pairing);

    // compare lhs and rhs

    if (!element_cmp(lhs, rhs)) {
        printf("Aggregate Signature Verifies\n");
    } else {
        printf("Aggregate Signature does not verify\n");
    }

    gettimeofday(end, NULL);

    seconds  = end->tv_sec  - start->tv_sec;
    useconds = end->tv_usec - start->tv_usec;
    bls_verification = seconds * 1e6 + useconds;

    printf("Elapsed Time: Verification of Signatures: %.0f microseconds\n", bls_verification);

    bls_total = bls_aggregation + bls_verification;

    printf("Elapsed Time: BLS Total: %.0f microseconds\n", bls_total);
    
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

    pairing_clear(pairing);

    return 0;
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

int generate_random_seckey(unsigned char *seckey) {
    // Generate random bytes for the secret key
    if (!RAND_bytes(seckey, 32)) {
        fprintf(stderr, "Failed to generate random secret key\n");
        return 1;
    }
}
