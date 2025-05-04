#ifndef SABER_ENCAP_HOOKS_H
#define SABER_ENCAP_HOOKS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "params.h"
#include "../../SABER/Reference_Implementation_KEM/SABER_params.h"
#include "../../SABER/Reference_Implementation_KEM/rng.h"
#include "../../SABER/Reference_Implementation_KEM/fips202.h"
#include "../../SABER/Reference_Implementation_KEM/SABER_indcpa.h"
#include "../../SABER/Reference_Implementation_KEM/pack_unpack.h"
#include "params.h"

//-----------------------------------------------------------------------------
// Внутренние типы «core»
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t sk[SABER_INDCPA_SECRETKEYBYTES];  // CPA-секретный ключ
    uint8_t z [Z_BYTES];                      // 32-байтовый секрет для KDF_fail
} sk_core_t;

typedef struct {
    uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES];  // CPA-публичный ключ
} pk_core_t;

typedef struct {
    uint8_t ct[SABER_BYTES_CCA_DEC];          // CPA-шифротекст
} ct_core_t;

//-----------------------------------------------------------------------------
// Основные «core» операции (реализации в encap_hooks.c)
//-----------------------------------------------------------------------------
void SaberCore_KeyGen(pk_core_t *pk_core, sk_core_t *sk_core);
void SaberCore_Encrypt(ct_core_t *c_core,
                       const pk_core_t *pk_core,
                       const uint8_t *m);
void SaberCore_Decrypt(uint8_t *m,
                       const sk_core_t *sk_core,
                       const ct_core_t *c_core);

//-----------------------------------------------------------------------------
// Сериализация / десериализация
//-----------------------------------------------------------------------------
static inline void serialize_pk(uint8_t *pk, const pk_core_t *pk_core) {
    memcpy(pk, pk_core->pk, SABER_INDCPA_PUBLICKEYBYTES);
}

static inline void deserialize_pk(pk_core_t *pk_core, const uint8_t *pk) {
    memcpy(pk_core->pk, pk, SABER_INDCPA_PUBLICKEYBYTES);
}

static inline void serialize_ct(uint8_t *ct,
                                const ct_core_t *c_core,
                                const uint8_t *d) {
    memcpy(ct, c_core->ct, SABER_BYTES_CCA_DEC);
    memcpy(ct + SABER_BYTES_CCA_DEC, d, D_BYTES);
}

static inline void deserialize_ct(ct_core_t *c_core,
                                  uint8_t *d,
                                  const uint8_t *ct) {
    memcpy(c_core->ct, ct, SABER_BYTES_CCA_DEC);
    memcpy(d, ct + SABER_BYTES_CCA_DEC, D_BYTES);
}

static inline void random_bytes(uint8_t *buf, size_t len) {
    // randombytes из rng.h
    randombytes(buf, len);
}

//-----------------------------------------------------------------------------
// Хэш-функции и KDF при ошибке
//-----------------------------------------------------------------------------
void H1(uint8_t *digest,
        const uint8_t *in1, size_t in1_len,
        const uint8_t *in2, size_t in2_len);

void H2(uint8_t *key,
        const uint8_t *in1, size_t in1_len,
        const uint8_t *in2, size_t in2_len);

void KDF_fail(uint8_t *key,
              const sk_core_t *sk_core,
              const uint8_t *c_core, size_t c_len);

#endif //SABER_ENCAP_HOOKS_H
