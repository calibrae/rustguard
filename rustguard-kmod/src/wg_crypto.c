// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — C shim for kernel crypto.
 *
 * Uses the same chacha20poly1305 library functions as the real kernel
 * WireGuard (lib/crypto/chacha20poly1305.c). No crypto API, no scatterlists,
 * no TFM allocation. Just buffers in, buffers out.
 *
 * Jason got this right — the kernel crypto API is for block devices and TLS.
 * WireGuard needs fast, simple, buffer-oriented crypto.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>

/* Prototypes. */
int wg_chacha20poly1305_encrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
int wg_chacha20poly1305_decrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
int wg_crypto_init(void);
void wg_crypto_exit(void);
void wg_blake2s_256(const u8 *data, u32 data_len, u8 out[32]);
void wg_blake2s_256_hmac(const u8 key[32], const u8 *data, u32 data_len, u8 out[32]);
void wg_blake2s_256_mac(const u8 *key, u32 key_len,
	const u8 *data, u32 data_len, u8 out[32]);
void wg_hkdf(const u8 key[32], const u8 *input, u32 input_len,
	u8 out1[32], u8 out2[32], u8 out3[32]);
void wg_get_random_bytes(u8 *buf, u32 len);

/*
 * ── ChaCha20-Poly1305 ────────────────────────────────────────────────
 *
 * Direct library calls — same as kernel WireGuard uses.
 * dst must have room for src_len + 16 (tag) on encrypt.
 * src_len includes the 16-byte tag on decrypt.
 */

int wg_chacha20poly1305_encrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	chacha20poly1305_encrypt(dst, src, src_len,
				 ad, ad_len, nonce, key);
	return 0;
}
EXPORT_SYMBOL_GPL(wg_chacha20poly1305_encrypt);

int wg_chacha20poly1305_decrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	if (src_len < CHACHA20POLY1305_AUTHTAG_SIZE)
		return -EINVAL;
	if (!chacha20poly1305_decrypt(dst, src, src_len,
				      ad, ad_len, nonce, key))
		return -EBADMSG;
	return 0;
}
EXPORT_SYMBOL_GPL(wg_chacha20poly1305_decrypt);

int wg_crypto_init(void) { return 0; }
EXPORT_SYMBOL_GPL(wg_crypto_init);

void wg_crypto_exit(void) {}
EXPORT_SYMBOL_GPL(wg_crypto_exit);

/*
 * ── BLAKE2s-256 ───────────────────────────────────────────────────────
 */

void wg_blake2s_256(const u8 *data, u32 data_len, u8 out[32])
{
	blake2s(out, data, NULL, BLAKE2S_HASH_SIZE, data_len, 0);
}
EXPORT_SYMBOL_GPL(wg_blake2s_256);

void wg_blake2s_256_mac(const u8 *key, u32 key_len,
	const u8 *data, u32 data_len, u8 out[32])
{
	blake2s(out, data, key, BLAKE2S_HASH_SIZE, data_len, key_len);
}
EXPORT_SYMBOL_GPL(wg_blake2s_256_mac);

void wg_blake2s_256_hmac(const u8 key[32], const u8 *data, u32 data_len, u8 out[32])
{
	struct blake2s_state state;
	u8 padded_key[BLAKE2S_BLOCK_SIZE];
	u8 ipad[BLAKE2S_BLOCK_SIZE];
	u8 opad[BLAKE2S_BLOCK_SIZE];
	u8 inner_hash[BLAKE2S_HASH_SIZE];
	int i;

	memset(padded_key, 0, BLAKE2S_BLOCK_SIZE);
	memcpy(padded_key, key, 32);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; i++) {
		ipad[i] = padded_key[i] ^ 0x36;
		opad[i] = padded_key[i] ^ 0x5c;
	}

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, ipad, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, data, data_len);
	blake2s_final(&state, inner_hash);

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, opad, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, inner_hash, BLAKE2S_HASH_SIZE);
	blake2s_final(&state, out);

	memzero_explicit(padded_key, sizeof(padded_key));
	memzero_explicit(ipad, sizeof(ipad));
	memzero_explicit(opad, sizeof(opad));
	memzero_explicit(inner_hash, sizeof(inner_hash));
}
EXPORT_SYMBOL_GPL(wg_blake2s_256_hmac);

void wg_hkdf(const u8 key[32], const u8 *input, u32 input_len,
	u8 out1[32], u8 out2[32], u8 out3[32])
{
	u8 prk[32];
	u8 t_input[33];

	wg_blake2s_256_hmac(key, input, input_len, prk);

	t_input[0] = 0x01;
	wg_blake2s_256_hmac(prk, t_input, 1, out1);

	memcpy(t_input, out1, 32);
	t_input[32] = 0x02;
	wg_blake2s_256_hmac(prk, t_input, 33, out2);

	if (out3) {
		memcpy(t_input, out2, 32);
		t_input[32] = 0x03;
		wg_blake2s_256_hmac(prk, t_input, 33, out3);
	}

	memzero_explicit(prk, sizeof(prk));
	memzero_explicit(t_input, sizeof(t_input));
}
EXPORT_SYMBOL_GPL(wg_hkdf);

void wg_get_random_bytes(u8 *buf, u32 len)
{
	get_random_bytes(buf, len);
}
EXPORT_SYMBOL_GPL(wg_get_random_bytes);
