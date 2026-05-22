#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stddef.h>

void hash_shake256(const uint8_t *prefix, size_t prefix_len,const uint8_t *data, size_t data_len,uint8_t *out);

#endif