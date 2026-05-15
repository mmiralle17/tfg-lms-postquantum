#include <openssl/evp.h>
#include <string.h>
#include "config.h"

// Función auxiliar para SHAKE-256
// Concatena prefix + data y devuelve el hash en 'out'
void hash_shake256(const uint8_t *prefix, size_t prefix_len,const uint8_t *data, size_t data_len,uint8_t *out) {
    
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_shake256(); // Usamos SHAKE256

    mdctx = EVP_MD_CTX_new(); //reservo memoria para la operacion hash
    EVP_DigestInit_ex(mdctx, md, NULL); //inicializo shake256 para seleccionar shake256

    // 1. Alimentamos el prefijo (normalmente I, q, i...)
    if (prefix != NULL && prefix_len > 0) {
        EVP_DigestUpdate(mdctx, prefix, prefix_len); //introduzco los datos, le paso el mensaje
    }

    // 2. Alimentamos los datos
    if (data != NULL && data_len > 0) {
        EVP_DigestUpdate(mdctx, data, data_len);
    }

    // 3. Extraemos la salida (XOF permite longitud variable, pedimos HASH_LEN)
    EVP_DigestFinalXOF(mdctx, out, HASH_LEN);

    EVP_MD_CTX_free(mdctx);
}