#ifndef LMS_H
#define LMS_H

#include <stdint.h>
#include "config.h"

// Constantes de dominio (RFC 8554) para diferenciar qué estamos hasheando
#define D_LEAF 0x8282  // Para hashear una hoja
#define D_INTR 0x8383  // Para hashear un nodo interno

// Altura del árbol para pruebas (H=3 implica 2^3 = 8 hojas)
#define TREE_H 15
#define N_LEAVES (1 << TREE_H)          // 2^H
#define N_NODES  (1 << (TREE_H + 1))    // Total de nodos en el array (2^(H+1))

// Estructura para guardar la clave privada completa (el estado)
typedef struct {
    uint8_t I[16];      // Identificador único del árbol
    uint32_t q;         // Índice de la hoja actual (para firmar)
    // En una implementación real, guardaríamos las semillas aquí.
    // Para simplificar, regeneraremos las claves OTS al vuelo o las guardaremos en RAM.
} lms_private_key_t;

// Función para construir el árbol completo y devolver la raíz
// pub_key_out: Donde guardaremos el hash raíz (32 bytes)
// I: Identificador del árbol
void lms_gen_public_key(uint8_t *pub_key_out, const uint8_t *I);

void lms_sign(uint8_t *sig_out, const uint8_t *msg, const uint8_t *priv_key, const uint8_t *I, uint32_t q);

int lms_verify(const uint8_t *root_pub_key, const uint8_t *signature, const uint8_t *msg, const uint8_t *I);

#endif