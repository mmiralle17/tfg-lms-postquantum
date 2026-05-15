#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

// Parámetros para LMS con SHAKE-256
#define HASH_LEN 32         // m = 32 bytes (256 bits)
#define W_PARAM 8           // Winternitz w = 8 
#define H_TREE_HEIGHT 10    // Altura del árbol 

// Identificadores de tipo
#define LMOTS_SHA256_N32_W8 0x00000004

#endif
