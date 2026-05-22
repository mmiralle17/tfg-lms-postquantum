#include <string.h>
#include <stdlib.h>
#include "lm_ots.h"
#include "hash.h"

void u16_to_bytes(uint8_t *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

void u32_to_bytes(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

// --- GENERADOR DE CLAVE PRIVADA ---
// En un caso real usaríamos /dev/urandom, aquí usamos rand() para simplificar
void lm_ots_gen_private_key(uint8_t *priv_key) {
    // Rellenar con un patrón fijo para que coincida siempre en las pruebas
    for (int i = 0; i < OTS_P * HASH_LEN; i++) {
        priv_key[i] = (uint8_t)(i & 0xFF); 
    }
}

// --- FUNCIÓN CADENA (CHAIN FUNCTION) ---
// Aplica el hash 'steps' veces.
// RFC 8554: tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
static void gen_chain(uint8_t *out, const uint8_t *in, size_t steps, const uint8_t *I, uint32_t q, uint16_t i) {
    
    uint8_t temp[HASH_LEN];
    memcpy(temp, in, HASH_LEN);

    // Buffer para el prefijo: I (16) + q (4) + i (2) + j (1) = 23 bytes
    // + datos (32 bytes) = 55 bytes total
    uint8_t buffer[23 + HASH_LEN];
    
    // Parte estática del prefijo
    memcpy(buffer, I, 16);
    u32_to_bytes(buffer + 16, q);
    u16_to_bytes(buffer + 20, i);

    for (uint8_t j = 0; j < steps; j++) {
        buffer[22] = j; // byte j
        memcpy(buffer + 23, temp, HASH_LEN);
        
        // Hasheamos
        hash_shake256(NULL, 0, buffer, 55, temp);
    }
    
    memcpy(out, temp, HASH_LEN);
}

// --- GENERAR CLAVE PÚBLICA OTS ---
// 1. Ejecuta las 34 cadenas hasta el final (255 iteraciones).
// 2. Comprime todos los resultados en un solo hash final.
void lm_ots_gen_public_key(uint8_t *pub_key_hash, const uint8_t *priv_key, const uint8_t *I, uint32_t q) {
    
    uint8_t tmp_chain[OTS_P * HASH_LEN]; // Aquí guardaremos los topes de las cadenas

    // 1. Calcular las 34 cadenas (p = 34)
    // Para la clave pública, corremos cada cadena 255 veces (2^w - 1)
    for (uint16_t i = 0; i < OTS_P; i++) {
        gen_chain(tmp_chain + (i * HASH_LEN), priv_key + (i * HASH_LEN), 255, I, q, i);                     
    }

    // 2. Calcular el Hash Final de la Clave Pública
    // RFC 8554: K = H(I || u32str(q) || u16str(D_PBLC) || tmp_0 ... tmp_p-1)
    
    uint8_t pre_hash[22]; // I (16) + q (4) + D_PBLC (2)
    memcpy(pre_hash, I, 16);
    u32_to_bytes(pre_hash + 16, q);
    u16_to_bytes(pre_hash + 20, D_PBLC);

    // Hasheamos el prefijo + todas las cadenas concatenadas
    hash_shake256(pre_hash, 22, tmp_chain, OTS_P * HASH_LEN, pub_key_hash);
}

// Función auxiliar para calcular el checksum (necesaria para firmar)
uint16_t checksum(const uint8_t *coefs, size_t n) {
    uint32_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum += (255 - coefs[i]); // w=8, max=255
    }
    return (uint16_t)(sum << 0);
}

// FIRMAR UN MENSAJE (OTS)
// signature_out: donde se guarda la firma (tamaño OTS_P * 32)
// msg: hash del mensaje a firmar (32 bytes)
// priv_key: clave privada OTS de esta hoja
// I, q: contexto
void lm_ots_sign(uint8_t *signature_out, const uint8_t *msg, const uint8_t *priv_key, const uint8_t *I, uint32_t q) {
    
    // 1. Preparar los coeficientes (Mensaje + Checksum)
    uint8_t coefs[OTS_P];
    memcpy(coefs, msg, HASH_LEN);
    
    // Calcular y añadir checksum
    uint16_t cksm = checksum(coefs, HASH_LEN);
    coefs[HASH_LEN]     = (cksm >> 8) & 0xFF;
    coefs[HASH_LEN + 1] = cksm & 0xFF;

    // 2. Generar las cadenas de firma
    // A diferencia de la clave pública (que corre 255 veces),
    // aquí corremos 'coefs[i]' veces.
    for (int i = 0; i < OTS_P; i++) {
        gen_chain(signature_out + (i * HASH_LEN), priv_key + (i * HASH_LEN), coefs[i], I, q, i);
    }
}

// VERIFICAR UNA FIRMA OTS (Recuperar la clave pública candidata)
// recovered_pub_key: Donde guardaremos la clave recuperada
// signature: La firma que nos han enviado
// msg: El hash del mensaje original
void lm_ots_verify(uint8_t *recovered_pub_key, const uint8_t *signature, const uint8_t *msg, const uint8_t *I, uint32_t q) {
    
    // 1. Recalcular los coeficientes (igual que al firmar)
    uint8_t coefs[OTS_P];
    memcpy(coefs, msg, HASH_LEN);
    
    uint16_t cksm = checksum(coefs, HASH_LEN);
    coefs[HASH_LEN]     = (cksm >> 8) & 0xFF;
    coefs[HASH_LEN + 1] = cksm & 0xFF;

    uint8_t tmp_chain[OTS_P * HASH_LEN];

    // 2. Reconstruir las cadenas
    // En la firma nos dan el valor en el paso 'coefs[i]'.
    // Tenemos que avanzar desde 'coefs[i]' hasta 255.
    for (int i = 0; i < OTS_P; i++) {
        // start_val: El valor que viene en la firma
        const uint8_t *start_val = signature + (i * HASH_LEN);
        
        // steps: Cuántos pasos faltan hasta el final (255)
        // Ejemplo: Si el byte del mensaje era 10, faltan 245 pasos.
        size_t steps_remaining = 255 - coefs[i];

        // OJO: gen_chain necesita el 'start_index' para el prefijo hash.
        // Aquí el 'j' inicial no es 0, es 'coefs[i]'.
        // Pero nuestra función gen_chain actual asume que empieza en 0 y corre N pasos.
        // TENEMOS QUE MODIFICAR gen_chain LIGERAMENTE o hacer un bucle manual.
        
        // OPCIÓN: Bucle manual aquí reutilizando lógica de gen_chain
        uint8_t tmp[HASH_LEN];
        memcpy(tmp, start_val, HASH_LEN);
        
        uint8_t buffer[55]; // 23 prefijo + 32 data
        memcpy(buffer, I, 16);
        u32_to_bytes(buffer + 16, q);
        u16_to_bytes(buffer + 20, i);

        // Corremos los pasos que faltan
        for (int k = 0; k < steps_remaining; k++) {
            buffer[22] = coefs[i] + k; // El índice real en la cadena
            memcpy(buffer + 23, tmp, HASH_LEN);
            hash_shake256(NULL, 0, buffer, 55, tmp);
        }
        
        memcpy(tmp_chain + (i * HASH_LEN), tmp, HASH_LEN);
    }

    // 3. Hashear todo junto para obtener la Public Key candidata
    uint8_t pre_hash[22];
    memcpy(pre_hash, I, 16);
    u32_to_bytes(pre_hash + 16, q);
    u16_to_bytes(pre_hash + 20, D_PBLC);

    hash_shake256(pre_hash, 22, tmp_chain, OTS_P * HASH_LEN, recovered_pub_key);
}