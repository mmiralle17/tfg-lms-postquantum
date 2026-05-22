#ifndef LMOTS_H
#define LMOTS_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

// Constantes definidas en RFC 8554
#define D_PBLC 0x8080  // Identificador para hashear la clave pública OTS

// Para SHA-256/256 y W=8:
// n = 32 bytes
// p = 34 cadenas (32 para el mensaje + 2 para el checksum)
// ls = 0 (left shift)
#define OTS_P 34 

// Genera una clave privada OTS (aleatoria)
void lm_ots_gen_private_key(uint8_t *priv_key);

// Genera la clave pública OTS a partir de la privada
// I: Identificador del árbol (16 bytes)
// q: Número de hoja (4 bytes)
void lm_ots_gen_public_key(uint8_t *pub_key_hash, const uint8_t *priv_key, const uint8_t *I, uint32_t q);

void lm_ots_sign(uint8_t *signature_out, const uint8_t *msg, const uint8_t *priv_key, const uint8_t *I, uint32_t q);

void lm_ots_verify(uint8_t *recovered_pub_key, const uint8_t *signature, const uint8_t *msg, const uint8_t *I, uint32_t q);

#endif