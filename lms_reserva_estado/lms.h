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

#define RESERVA_ESTADO 100  // N: Número de firmas que reservamos de golpe en disco

// Estructura para guardar la clave privada completa (el estado)
typedef struct {
    uint8_t I[16];      // Identificador único del árbol
    
    // --- NUEVO: Control de Estado ---
    uint32_t q;         // Índice actual en RAM (la próxima hoja que vamos a usar)
    uint32_t max_q;     // Límite reservado en disco (cuando q == max_q, toca escribir en NVRAM)
    
} lms_private_key_t;

// Función para construir el árbol completo y devolver la raíz
// pub_key_out: Donde guardaremos el hash raíz (32 bytes)
// I: Identificador del árbol
void lms_gen_public_key(uint8_t *pub_key_out, const uint8_t *I);

void lms_sign(uint8_t *sig_out, const uint8_t *msg, const uint8_t *priv_key, const uint8_t *I, uint32_t q);

int lms_verify(const uint8_t *root_pub_key, const uint8_t *signature, const uint8_t *msg, const uint8_t *I);

void lms_sign_with_reservation(uint8_t *sig_out, const uint8_t *msg, lms_private_key_t *priv_state, const uint8_t *ots_priv_key);

#endif