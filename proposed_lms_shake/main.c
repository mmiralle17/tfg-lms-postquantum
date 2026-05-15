#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> // Para medir tiempos
#include "hash.h"
#include "lm_ots.h"
#include "lms.h"

uint8_t saved_priv_key[OTS_P * HASH_LEN];

int main() {
    printf("=== PRUEBA RENDIMIENTO LMS SHAKE-256 (H=%d) ===\n", TREE_H);
    uint8_t I[16]; memset(I, 0xEE, 16);
    uint8_t root_pub[32];
    uint8_t msg[] = "Mensaje Secreto para el TFG";
    uint8_t signature[4 + (OTS_P * HASH_LEN) + (TREE_H * HASH_LEN)];
    clock_t start, end;

    // --- 1. KEYGEN ---
    start = clock();
    lm_ots_gen_private_key(saved_priv_key);
    lms_gen_public_key(root_pub, I);
    end = clock();
    printf("Tiempo KEYGEN: %f segundos\n", (double)(end - start) / CLOCKS_PER_SEC);

    // --- 2. SIGN ---
    start = clock();
    lms_sign(signature, msg, saved_priv_key, I, 0);
    end = clock();
    printf("Tiempo FIRMA:  %f segundos\n", (double)(end - start) / CLOCKS_PER_SEC);

    // --- 3. VERIFY ---
    start = clock();
    int result = lms_verify(root_pub, signature, msg, I);
    end = clock();
    printf("Tiempo VERIFICACION: %f segundos (Valida: %d)\n", (double)(end - start) / CLOCKS_PER_SEC, result);

    printf("==============================================\n\n");
    return 0;
}