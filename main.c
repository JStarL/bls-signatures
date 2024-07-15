#include <stdio.h>
#include <pbc/pbc.h>
#include <string.h>

void initialize_data_structure(element_t x, pairing_t pairing, char *type);

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
    element_t public_key, secret_key;
    element_t sig;
    element_t temp1, temp2;

    

    initialize_data_structure(g, pairing, "G2");
    initialize_data_structure(public_key, pairing, "G2");
    initialize_data_structure(h, pairing, "G1");
    initialize_data_structure(sig, pairing, "G1");
    initialize_data_structure(temp1, pairing, "GT");
    initialize_data_structure(temp2, pairing, "GT");
    initialize_data_structure(secret_key, pairing, "Zr");
    

    element_random(g);

    element_random(secret_key);

    element_pow_zn(public_key, g, secret_key);

    /*
    To implement, BLS Signature hashing
    */

    element_from_hash(h, "ABCDEF", 6);

    element_pow_zn(sig, h, secret_key);

    // Do pairings

    pairing_apply(temp1, sig, g, pairing);
    pairing_apply(temp2, h, public_key, pairing);

    // compare pairings

    if (!element_cmp(temp1, temp2)) {
        printf("Signature Verifies\n");
    } else {
        printf("Signature does not verify\n");
    }




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


