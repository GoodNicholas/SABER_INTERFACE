#include "../include/encap_hooks.h"
#include <string.h>

void SaberCore_KeyGen(pk_core_t *pk_core, sk_core_t *sk_core) {
    indcpa_kem_keypair(pk_core->pk, sk_core->sk);
    randombytes(sk_core->z, Z_BYTES);
}

// Core_Encrypt: шифрует m (длина SABER_KEYBYTES) в сырое c_core
void SaberCore_Encrypt(ct_core_t *c_core,
                       const pk_core_t *pk_core,
                       const uint8_t *m) {
    uint8_t coins[NOISE_BYTES];
    randombytes(coins, NOISE_BYTES);
    indcpa_kem_enc(m, coins, pk_core->pk, c_core->ct);
}

// Core_Decrypt: восстанавливает m' из сырых данных
void SaberCore_Decrypt(uint8_t *m,
                       const sk_core_t *sk_core,
                       const ct_core_t *c_core) {
    indcpa_kem_dec(sk_core->sk, c_core->ct, m);
}

// Контрольная метка d = H1(m || c_core)
void H1(uint8_t *digest,
        const uint8_t *in1, size_t in1_len,
        const uint8_t *in2, size_t in2_len) {
    size_t tot = in1_len + in2_len;
    uint8_t tmp[tot];
    memcpy(tmp, in1, in1_len);
    memcpy(tmp + in1_len, in2, in2_len);
    sha3_256(digest, tmp, tot);
}

// Общий секрет K = H2(m || c_core)
void H2(uint8_t *key,
        const uint8_t *in1, size_t in1_len,
        const uint8_t *in2, size_t in2_len) {
    size_t tot = in1_len + in2_len;
    uint8_t tmp[tot];
    memcpy(tmp, in1, in1_len);
    memcpy(tmp + in1_len, in2, in2_len);
    sha3_256(key, tmp, tot);
}

// KDF при провале проверки: просто хэшируем ciphertext
void KDF_fail(uint8_t *key,
              const sk_core_t *sk_core,
              const uint8_t *c_core, size_t c_len) {
    // Генерация ключа при ошибке
    sha3_256(key, c_core, c_len);
}