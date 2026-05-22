#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "lms.h"
#include "lm_ots.h"
#include "hash.h"

// Importamos funciones auxiliares que definimos en lm_ots.c
// (Lo ideal sería ponerlas en un common.h, pero para ir rápido las redeclaramos)
extern void u32_to_bytes(uint8_t *buf, uint32_t val);
extern void u16_to_bytes(uint8_t *buf, uint16_t val);

// Array global para guardar el árbol en memoria RAM
// El nodo 1 es la raíz. Los hijos del nodo k son 2k y 2k+1.
uint8_t tree[N_NODES][HASH_LEN];

// --- GENERAR UNA HOJA LMS ---
// Leaf = Hash(I || u32str(r) || u16str(D_LEAF) || OTS_PUB_KEY)
void gen_leaf(uint8_t *leaf_out, const uint8_t *I, uint32_t r, const uint8_t *ots_pub) {
    uint8_t buffer[16 + 4 + 2 + HASH_LEN];
    
    memcpy(buffer, I, 16);
    u32_to_bytes(buffer + 16, r);
    u16_to_bytes(buffer + 20, D_LEAF);
    memcpy(buffer + 22, ots_pub, HASH_LEN);
    
    hash_shake256(NULL, 0, buffer, sizeof(buffer), leaf_out);
}

// --- GENERAR NODO INTERNO ---
// Node = Hash(I || u32str(r) || u16str(D_INTR) || LEFT || RIGHT)
void gen_internal_node(uint8_t *node_out, const uint8_t *I, uint32_t r, const uint8_t *left, const uint8_t *right) {
    uint8_t buffer[16 + 4 + 2 + HASH_LEN + HASH_LEN];
    
    memcpy(buffer, I, 16);
    u32_to_bytes(buffer + 16, r);
    u16_to_bytes(buffer + 20, D_INTR);
    memcpy(buffer + 22, left, HASH_LEN);
    memcpy(buffer + 22 + HASH_LEN, right, HASH_LEN);
    
    hash_shake256(NULL, 0, buffer, sizeof(buffer), node_out);
}

// --- CONSTRUIR EL ÁRBOL ---
void lms_gen_public_key(uint8_t *pub_key_out, const uint8_t *I) {
    
    printf("[INFO] Generando %d hojas OTS...\n", N_LEAVES);

    // 1. Generar las Hojas (Leaves)
    // Las hojas en el array del árbol empiezan en el índice 2^H
    int leaf_start_idx = (1 << TREE_H);
    
    uint8_t priv_key[OTS_P * HASH_LEN];
    uint8_t ots_pub[HASH_LEN];

    for (int i = 0; i < N_LEAVES; i++) {
        // A) Generar OTS para esta hoja
        lm_ots_gen_private_key(priv_key); // ¡OJO! Esto es aleatorio. En real se derivaría de una semilla.
        lm_ots_gen_public_key(ots_pub, priv_key, I, i);
        
        // B) Convertir OTS Pub en Hoja LMS y guardarla en el árbol
        gen_leaf(tree[leaf_start_idx + i], I, leaf_start_idx + i, ots_pub);
        
        printf("."); fflush(stdout); // Progreso visual
    }
    printf("\n[INFO] Hojas generadas. Subiendo por el arbol...\n");

    // 2. Calcular Nodos Internos (Subir la pirámide)
    // Vamos desde el nivel de abajo (hojas) hacia arriba (raíz = nodo 1)
    for (int i = leaf_start_idx - 1; i > 0; i--) {
        gen_internal_node(tree[i], I, i, tree[2*i], tree[2*i + 1]);
    }

    // 3. La raíz está en tree[1]
    memcpy(pub_key_out, tree[1], HASH_LEN);
}

// Obtener el camino de autenticación para la hoja 'leaf_idx'
// path_out: Debe tener tamaño TREE_H * HASH_LEN
void get_auth_path(uint8_t *path_out, int leaf_idx) {
    // El nodo en el array global 'tree'
    // Las hojas empiezan en (1 << TREE_H)
    int node_idx = (1 << TREE_H) + leaf_idx;

    for (int i = 0; i < TREE_H; i++) {
        // El hermano es node_idx XOR 1
        // Si soy par (2), mi hermano es impar (3). Si soy impar (3), hermano par (2).
        int sibling_idx = node_idx ^ 1;
        
        // Copiar el hash del hermano al camino
        memcpy(path_out + (i * HASH_LEN), tree[sibling_idx], HASH_LEN);
        
        // Subir al padre
        node_idx = node_idx >> 1; // Dividir por 2
    }
}

// FIRMA LMS COMPLETA
// signature_out: q (4) + OTS sig + Auth Path
// msg: Mensaje original
// priv_key: Clave privada OTS (en real la regeneraríamos con semilla)
void lms_sign(uint8_t *sig_out, const uint8_t *msg, const uint8_t *priv_key, const uint8_t *I, uint32_t q) {
    
    // 1. Hashear el mensaje con un prefijo aleatorio "C" (Randomizer)
    // El RFC pide un valor C aleatorio de 32 bytes al inicio.
    // Simplificación: Usaremos C todo ceros para esta prueba.
    uint8_t C[32];
    memset(C, 0, 32);
    
    // Calcular Q = Hash(I || q || D_MESG || C || message)
    // Pero espera, lm_ots_sign espera el hash final.
    // Simplificación didáctica: Firmamos directamente SHAKE(msg)
    uint8_t msg_hash[HASH_LEN];
    hash_shake256(NULL, 0, msg, strlen((char*)msg), msg_hash);

    // 2. Escribir cabecera de la firma: q (4 bytes)
    u32_to_bytes(sig_out, q); // bytes 0-3
    
    // 3. Escribir firma OTS (bytes 4 en adelante)
    uint8_t *ots_sig_ptr = sig_out + 4;
    lm_ots_sign(ots_sig_ptr, msg_hash, priv_key, I, q);
    
    // 4. Escribir Camino de Autenticación (Auth Path)
    // Va justo después de la firma OTS
    uint8_t *path_ptr = ots_sig_ptr + (OTS_P * HASH_LEN);
    get_auth_path(path_ptr, q);
}


// Esta función representa la escritura lenta (cuello de botella)
void update_nvram_state(uint32_t next_reserved_q) {
    printf("[NVRAM] Escribiendo bloque en disco. Siguiente reserva hasta indice: %u\n", next_reserved_q);
    // Simular latencia física de escritura masiva en memoria Flash/EEPROM (IoT): 5ms
    usleep(5000);
}

// FIRMAR CON RESERVA DE ESTADO 
void lms_sign_with_reservation(uint8_t *sig_out, const uint8_t *msg, lms_private_key_t *priv_state, const uint8_t *ots_priv_key) {
    
    // 1. ¿Hemos agotado nuestra reserva en RAM?
    if (priv_state->q >= priv_state->max_q) {
        
        // Toca ir al disco para reservar el siguiente bloque de N firmas
        uint32_t nuevo_limite = priv_state->q + RESERVA_ESTADO;
        
        // Seguridad: Asegurarnos de no salirnos del árbol
        if (nuevo_limite > N_LEAVES) {
            nuevo_limite = N_LEAVES;
        }
        
        // Ejecutamos la operación lenta de I/O (Update-Before-Sign)
        update_nvram_state(nuevo_limite);
        
        // Actualizamos nuestra barrera en la RAM
        priv_state->max_q = nuevo_limite;
    }
    
    // 2. Proceder con la firma matemática (usando la RAM ultrarrápida)
    lms_sign(sig_out, msg, ots_priv_key, priv_state->I, priv_state->q);
    
    // 3. Consumimos una firma en memoria volátil (instantáneo, sin tocar disco)
    priv_state->q++;
}

// VERIFICAR FIRMA LMS
// Devuelve 1 si es válida, 0 si no.
// root_pub_key: La clave pública en la que confiamos
int lms_verify(const uint8_t *root_pub_key, const uint8_t *signature, const uint8_t *msg, const uint8_t *I) {
    
    // 1. Extraer q (índice de hoja) de la firma
    uint32_t q = (signature[0] << 24) | (signature[1] << 16) | (signature[2] << 8) | signature[3];
    
    // Punteros a las partes de la firma
    const uint8_t *ots_sig = signature + 4;
    const uint8_t *auth_path = signature + 4 + (OTS_P * HASH_LEN);

    // 2. Calcular Hash del mensaje
    uint8_t msg_hash[HASH_LEN];
    hash_shake256(NULL, 0, msg, strlen((char*)msg), msg_hash);

    // 3. Recuperar la Clave Pública OTS candidata
    uint8_t ots_pub_candidate[HASH_LEN];
    lm_ots_verify(ots_pub_candidate, ots_sig, msg_hash, I, q);

    // 4. Calcular la Hoja Candidata LMS
    // Leaf = Hash(I || q || D_LEAF || OTS_PUB)
    uint8_t node_val[HASH_LEN];
    gen_leaf(node_val, I, (1 << TREE_H) + q, ots_pub_candidate);

    // 5. Subir por el árbol usando el Auth Path
    uint32_t node_idx = (1 << TREE_H) + q;
    
    for (int i = 0; i < TREE_H; i++) {
        // Extraer hermano del camino
        const uint8_t *sibling = auth_path + (i * HASH_LEN);
        
        uint8_t buffer[16 + 4 + 2 + 64]; // I + r + type + left + right
        memcpy(buffer, I, 16);
        u32_to_bytes(buffer + 16, node_idx >> 1); // Indice del padre
        u16_to_bytes(buffer + 20, D_INTR);

        // Decidir orden (Izquierda/Derecha)
        if (node_idx % 2 == 0) { // Soy hijo izquierdo (par)
            memcpy(buffer + 22, node_val, HASH_LEN); // Yo primero
            memcpy(buffer + 54, sibling, HASH_LEN);  // Hermano después
        } else { // Soy hijo derecho (impar)
            memcpy(buffer + 22, sibling, HASH_LEN);  // Hermano primero
            memcpy(buffer + 54, node_val, HASH_LEN); // Yo después
        }
        
        // Calcular padre
        hash_shake256(NULL, 0, buffer, sizeof(buffer), node_val);
        
        // Subir nivel
        node_idx >>= 1;
    }

    // 6. Comparar la raíz calculada (node_val) con la real
    if (memcmp(node_val, root_pub_key, HASH_LEN) == 0) {
        return 1; // ¡VALIDO!
    } else {
        return 0; // invalido
    }
}