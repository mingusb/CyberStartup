#ifndef _SGX_TCRYPTO_H_
#define _SGX_TCRYPTO_H_

#include <stdint.h>

typedef uint8_t sgx_sha256_hash_t[32];
typedef void* sgx_aes_gcm_128bit_key_t;
typedef void* sgx_aes_gcm_128bit_tag_t;

int sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len, sgx_sha256_hash_t *p_hash);
int sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len, sgx_aes_gcm_128bit_tag_t *p_out_mac);
int sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len, const sgx_aes_gcm_128bit_tag_t *p_in_mac);

#endif
