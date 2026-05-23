# Análisis e Implementación del Esquema LMS para Criptografía Post-Cuántica

Repositorio oficial del Trabajo Fin de Grado (TFG) en Ingeniería Informática. Universidad Complutense de Madrid (Curso 2025-2026).

**Autora:** María Magdalena Miralles Reyes  
**Directores:** José Luis Imaña Pascual y Sergio Bernabé García  

---

## 📌 Descripción del Proyecto

Este proyecto aborda la transición hacia la criptografía post-cuántica mediante el análisis y la implementación del esquema **Leighton-Micali Signature (LMS)**, estandarizado por el NIST (SP 800-208) y el IETF (RFC 8554). 

El objetivo principal es evaluar el rendimiento de este esquema *stateful* basado en hash, proponiendo una arquitectura que sustituye la primitiva tradicional SHA-256 por funciones de salida extendida (**XOF**) de la familia SHA-3, concretamente **SHAKE-256**.

## 📂 Estructura del Repositorio

Para garantizar la comparabilidad de los resultados y aislar las métricas, el desarrollo se ha dividido en dos paradigmas de implementación diferenciados:

* `/reference_cisco`: Contiene la adaptación de la **Implementación de Referencia** basada en el repositorio oficial de Cisco. Opera bajo la arquitectura jerárquica HSS utilizando SHA-256.
* `/proposed_lms_shake`: Contiene la **Implementación Propuesta**. Código desarrollado íntegramente desde cero en C para explotar la eficiencia de SHAKE-256 en la capa base LMS, simplificando la gestión de máscaras criptográficas.
* `/lms_reserva_estado`: Contiene la instrumentación y simulación del mecanismo de Reserva Anticipada de Estado (State Reservation). Esta variante mitiga el severo cuello de botella de E/S de la memoria no volátil delegando la gestión transaccional a la memoria RAM mediante la reserva de bloques de índices
* `/HSS_SHA-256_resuls.csv`: Contiene los resultados de la **Implementación de Referencia**. Estos resultados son los que se utilizan en la memoria del tfg.
* `/LMS_SHAKE-256_resuls.csv`: Contiene los resultados de la **Implementación Propuesta**. Estos resultados son los que se utilizan en la memoria del tfg.

## 🚀 Compilación y Ejecución (macOS / Linux)

Ambas implementaciones están escritas en C y requieren un compilador estándar (GCC/Clang). En sistemas macOS (Apple Silicon), puede ser necesaria la librería de soporte OpenSSL para ciertos módulos de compatibilidad.

**Para compilar la implementación propuesta:**
1. Se clona este repositorio `git clone https://github.com/mmiralle17/tfg-lms-postquantum.git`
2. cd `tfg-lms-postquantum`
3. Si se quiere ejecutar la implementacion propuesta hacemos `cd proposed_lms_shake`
4. make
5. ./(nombre que genera el makefile)
   
## 📊 Principales Resultados

Como se detalla en la memoria del proyecto, la implementación basada en SHAKE-256 demuestra una competitividad excepcional en entornos asimétricos, logrando tiempos de verificación de **0.004 segundos** independientemente de la altura del árbol de Merkle ($h$), confirmando su viabilidad para ecosistemas con recursos limitados como dispositivos IoT.
* **Escalabilidad Jerárquica (HSS):** Se demuestra empíricamente la necesidad de la arquitectura *Hierarchical Signature System* para infraestructuras masivas. Para generar una capacidad de 1 millón de firmas ($h_{total}=20$), la topología jerárquica equilibrada ($L=2$) reduce el tiempo de bloqueo de inicialización (KeyGen) de **30 minutos** a tan solo **1.84 segundos**, difiriendo el coste computacional restante bajo demanda.
* **Gestión del Estado y Rendimiento:** Se ha demostrado empíricamente que el paradigma de persistencia estricta en almacenamiento no volátil supone un severo cuello de botella de E/S. La implementación del mecanismo de **Reserva Anticipada de Estado** ha logrado incrementar el rendimiento transaccional del sistema en un **42%** (alcanzando más de 293 firmas por segundo), mitigando las latencias de disco y viabilizando su uso en entornos concurrentes.
