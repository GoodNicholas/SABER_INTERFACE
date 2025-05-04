// src/kem.c
#include <string.h>
#include "../include/api.h"
#include "../include/encap_hooks.h"

/* Размеры структур из encap_hooks.h */
#define SK_CORE_BYTES    sizeof(sk_core_t)
#define PK_BYTES         SABER_INDCPA_PUBLICKEYBYTES
#define CT_CORE_BYTES    sizeof(ct_core_t)

/* KeyGen: core + сериализация */
int Saber_KeyGen(uint8_t *pk, uint8_t *sk) {
    sk_core_t sk_core;
    pk_core_t pk_core;

    // 1. Сгенерировать ключи ядра
    SaberCore_KeyGen(&pk_core, &sk_core);

    // 2. Сериализовать публичный ключ
    serialize_pk(pk, &pk_core);

    // 3. Сгенерировать z и включить в sk_core (если ещё не сделано внутри)
    random_bytes(sk_core.z, Z_BYTES);

    // 4. Собрать полный sk = sk_core || pk || z
    memcpy(sk, (uint8_t *)&sk_core, SK_CORE_BYTES);
    memcpy(sk + SK_CORE_BYTES, pk, PK_BYTES);

    return 0;
}

/* Encaps: десериализация pk, core-шифрование + хэши */
int Saber_Encaps(const uint8_t *pk, uint8_t *ct, uint8_t *shared_key) {
    pk_core_t pk_core;
    ct_core_t c_core;
    uint8_t m[MSG_BYTES];
    uint8_t d[D_BYTES];

    // восстановить внутреннее представление публичного ключа
    deserialize_pk(&pk_core, pk);

    // случайное сообщение m
    random_bytes(m, MSG_BYTES);

    // core-шифрование
    SaberCore_Encrypt(&c_core, &pk_core, m);

    // d = H1(m || c_core)
    H1(d, m, MSG_BYTES, (uint8_t *)&c_core, CT_CORE_BYTES);

    // сериализовать ct = c_core || d
    serialize_ct(ct, &c_core, d);

    // shared_key = H2(m || c_core)
    H2(shared_key, m, MSG_BYTES, (uint8_t *)&c_core, CT_CORE_BYTES);

    return 0;
}

/* Decaps: core-расшифрование + проверка метки */
int Saber_Decaps(const uint8_t *sk, const uint8_t *ct, uint8_t *shared_key) {
    sk_core_t sk_core;
    ct_core_t c_core;
    uint8_t pk_copy[PK_BYTES];
    uint8_t d[D_BYTES], d_check[D_BYTES];
    uint8_t m_prime[MSG_BYTES];

    // разделить sk на sk_core и копию pk
    memcpy(&sk_core, sk, SK_CORE_BYTES);
    memcpy(pk_copy, sk + SK_CORE_BYTES, PK_BYTES);

    // десериализовать ct
    deserialize_ct(&c_core, d, ct);

    // core-расшифрование
    SaberCore_Decrypt(m_prime, &sk_core, &c_core);

    // проверка d
    H1(d_check, m_prime, MSG_BYTES, (uint8_t *)&c_core, CT_CORE_BYTES);
    if (memcmp(d, d_check, D_BYTES) == 0) {
        // корректно
        H2(shared_key, m_prime, MSG_BYTES, (uint8_t *)&c_core, CT_CORE_BYTES);
    } else {
        // не прошло проверку — KDF_fail
        KDF_fail(shared_key, &sk_core, (uint8_t *)&c_core, CT_CORE_BYTES);
    }

    return 0;
}
