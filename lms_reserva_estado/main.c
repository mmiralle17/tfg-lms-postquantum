#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> 
#include <unistd.h>
#include "hash.h"
#include "lm_ots.h"
#include "lms.h"

uint8_t saved_priv_key[OTS_P * HASH_LEN];

// Función auxiliar para simular el cuello de botella estricto (escribir en disco)
void simulador_disco_estricto(uint32_t q) {
    FILE *f = fopen("disco_estricto.bin", "wb");
    if(f) {
        fwrite(&q, sizeof(uint32_t), 1, f);
        fclose(f);
    }
    // Simular latencia física de escritura en memoria Flash/EEPROM (IoT): 5ms
    usleep(5000); 
}

int main() {
    printf("=== PRUEBA RENDIMIENTO LMS SHAKE-256 (H=%d) ===\n", TREE_H);
    uint8_t I[16]; memset(I, 0xEE, 16);
    uint8_t root_pub[32];
    uint8_t msg[] = "Mensaje Secreto para el TFG";
    uint8_t signature[4 + (OTS_P * HASH_LEN) + (TREE_H * HASH_LEN)];
    clock_t start, end;

    // --- 1. KEYGEN ---
    printf("\n[1] Generando Claves...\n");
    start = clock();
    lm_ots_gen_private_key(saved_priv_key);
    lms_gen_public_key(root_pub, I);
    end = clock();
    printf("Tiempo KEYGEN: %f segundos\n", (double)(end - start) / CLOCKS_PER_SEC);

    // EXPERIMENTO 1: PERSISTENCIA ESTRICTA (El método antiguo, lento)
    printf("\n[2] EXPERIMENTO: Persistencia Estricta (1000 firmas)\n");
    int num_firmas = 1000;
    
    start = clock();
    for(int i = 0; i < num_firmas; i++) {
        // En el modelo estricto, escribimos en el disco físico ANTES de cada firma
        simulador_disco_estricto(i);
        lms_sign(signature, msg, saved_priv_key, I, i);
    }
    end = clock();
    double tiempo_estricto = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Tiempo total 1000 firmas (Estricto): %f segundos\n", tiempo_estricto);
    printf("Rendimiento: %.2f firmas/segundo\n", num_firmas / tiempo_estricto);

    // EXPERIMENTO 2: RESERVA DE ESTADO (La nueva implementación, rápida)
    printf("\n[3] EXPERIMENTO: Reserva de Estado en RAM (1000 firmas, N=%d)\n", RESERVA_ESTADO);
    
    // Inicializamos el estado para la nueva función
    lms_private_key_t estado_firma;
    memcpy(estado_firma.I, I, 16);
    estado_firma.q = 0;
    estado_firma.max_q = 0; 
    
    start = clock();
    for(int i = 0; i < num_firmas; i++) {
        // La propia función ya gestiona cuándo ir al disco (cada 100 firmas)
        lms_sign_with_reservation(signature, msg, &estado_firma, saved_priv_key);
    }
    end = clock();
    double tiempo_reserva = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Tiempo total 1000 firmas (Reserva):  %f segundos\n", tiempo_reserva);
    printf("Rendimiento: %.2f firmas/segundo\n", num_firmas / tiempo_reserva);

    // 3. VERIFY 
    printf("\n[4] Verificando la ultima firma generada...\n");
    start = clock();
    int result = lms_verify(root_pub, signature, msg, I);
    end = clock();
    printf("Tiempo VERIFICACION: %f segundos (Valida: %d)\n", (double)(end - start) / CLOCKS_PER_SEC, result);

    printf("\n=== CONCLUSION PARA EL CAPITULO 4 ===\n");
    printf("Mejora de velocidad lograda: %.2fx mas rapido\n", tiempo_estricto / tiempo_reserva);
    printf("==============================================\n\n");

    return 0;
}