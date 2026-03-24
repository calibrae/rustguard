// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — C shim for kernel crypto API.
 *
 * Wraps the kernel's hardware-accelerated crypto primitives:
 *   - ChaCha20-Poly1305 AEAD (encrypt/decrypt transport packets)
 *   - BLAKE2s-256 hash (handshake, MAC, HKDF)
 *   - Curve25519 DH (key exchange)
 *
 * The kernel's ChaCha20 is hand-tuned ASM on x86 (AVX2/AVX-512),
 * which is why we're here instead of pure Rust.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <crypto/blake2s.h>
#include <crypto/curve25519.h>

/* Prototypes for exported functions. */
int wg_chacha20poly1305_encrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
int wg_chacha20poly1305_decrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
void wg_blake2s_256(const u8 *data, u32 data_len, u8 out[32]);
void wg_blake2s_256_hmac(const u8 key[32], const u8 *data, u32 data_len, u8 out[32]);
void wg_blake2s_256_mac(const u8 *key, u32 key_len,
	const u8 *data, u32 data_len, u8 out[32]);
void wg_hkdf(const u8 key[32], const u8 *input, u32 input_len,
	u8 out1[32], u8 out2[32], u8 out3[32]);
int wg_curve25519(u8 out[32], const u8 scalar[32], const u8 point[32]);
void wg_curve25519_generate_secret(u8 secret[32]);
void wg_curve25519_generate_public(u8 pub_key[32], const u8 secret[32]);
void wg_get_random_bytes(u8 *buf, u32 len);

/*
 * ── ChaCha20-Poly1305 AEAD ───────────────────────────────────────────
 *
 * WireGuard transport: nonce = 4 zero bytes || 8-byte LE counter.
 * Returns 0 on success, negative on error.
 */

int wg_chacha20poly1305_encrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg_src, sg_dst;
	u8 iv[12];
	int ret;

	tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_aead_setkey(tfm, key, 32);
	if (ret)
		goto out_free_tfm;

	crypto_aead_setauthsize(tfm, 16);

	req = aead_request_alloc(tfm, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	/* Build WireGuard nonce: 4 zero bytes || 8-byte LE counter */
	memset(iv, 0, 4);
	memcpy(iv + 4, &nonce, 8);

	/* Copy src to dst first — AEAD encrypts in-place */
	memcpy(dst, src, src_len);

	sg_init_one(&sg_src, dst, src_len + 16);
	sg_init_one(&sg_dst, dst, src_len + 16);

	aead_request_set_crypt(req, &sg_src, &sg_dst, src_len, iv);
	aead_request_set_ad(req, ad_len);

	/* If we have AD, we need a more complex SG setup */
	if (ad_len > 0) {
		struct scatterlist sg[2];
		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], ad, ad_len);
		sg_set_buf(&sg[1], dst, src_len + 16);
		aead_request_set_crypt(req, sg, sg, src_len, iv);
		aead_request_set_ad(req, ad_len);
	}

	ret = crypto_aead_encrypt(req);

	aead_request_free(req);
out_free_tfm:
	crypto_free_aead(tfm);
	return ret;
}
EXPORT_SYMBOL_GPL(wg_chacha20poly1305_encrypt);

int wg_chacha20poly1305_decrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg_src, sg_dst;
	u8 iv[12];
	int ret;

	if (src_len < 16)
		return -EINVAL;

	tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_aead_setkey(tfm, key, 32);
	if (ret)
		goto out_free_tfm;

	crypto_aead_setauthsize(tfm, 16);

	req = aead_request_alloc(tfm, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	memset(iv, 0, 4);
	memcpy(iv + 4, &nonce, 8);

	memcpy(dst, src, src_len);

	sg_init_one(&sg_src, dst, src_len);
	sg_init_one(&sg_dst, dst, src_len);

	aead_request_set_crypt(req, &sg_src, &sg_dst, src_len, iv);
	aead_request_set_ad(req, ad_len);

	if (ad_len > 0) {
		struct scatterlist sg[2];
		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], ad, ad_len);
		sg_set_buf(&sg[1], dst, src_len);
		aead_request_set_crypt(req, sg, sg, src_len, iv);
		aead_request_set_ad(req, ad_len);
	}

	ret = crypto_aead_decrypt(req);

	aead_request_free(req);
out_free_tfm:
	crypto_free_aead(tfm);
	return ret;
}
EXPORT_SYMBOL_GPL(wg_chacha20poly1305_decrypt);

/*
 * ── BLAKE2s-256 ───────────────────────────────────────────────────────
 */

void wg_blake2s_256(const u8 *data, u32 data_len, u8 out[32])
{
	blake2s(out, data, NULL, BLAKE2S_HASH_SIZE, data_len, 0);
}
EXPORT_SYMBOL_GPL(wg_blake2s_256);

/* Keyed BLAKE2s MAC — used for MAC1/MAC2 in WireGuard. */
void wg_blake2s_256_mac(const u8 *key, u32 key_len,
	const u8 *data, u32 data_len, u8 out[32])
{
	blake2s(out, data, key, BLAKE2S_HASH_SIZE, data_len, key_len);
}
EXPORT_SYMBOL_GPL(wg_blake2s_256_mac);

/*
 * HMAC-BLAKE2s — used in WireGuard's HKDF.
 * Standard HMAC construction: H((K ^ opad) || H((K ^ ipad) || msg))
 */
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

	/* Inner: H(ipad || data) */
	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, ipad, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, data, data_len);
	blake2s_final(&state, inner_hash);

	/* Outer: H(opad || inner_hash) */
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

/*
 * HKDF using HMAC-BLAKE2s. Extracts + expands to 3 outputs.
 * out3 may be NULL if only 2 outputs are needed.
 */
void wg_hkdf(const u8 key[32], const u8 *input, u32 input_len,
	u8 out1[32], u8 out2[32], u8 out3[32])
{
	u8 prk[32];
	u8 t_input[33]; /* 32 bytes previous T || 1 byte counter */

	/* Extract: PRK = HMAC(key, input) */
	wg_blake2s_256_hmac(key, input, input_len, prk);

	/* Expand T1 = HMAC(PRK, 0x01) */
	t_input[0] = 0x01;
	wg_blake2s_256_hmac(prk, t_input, 1, out1);

	/* Expand T2 = HMAC(PRK, T1 || 0x02) */
	memcpy(t_input, out1, 32);
	t_input[32] = 0x02;
	wg_blake2s_256_hmac(prk, t_input, 33, out2);

	/* Expand T3 = HMAC(PRK, T2 || 0x03) */
	if (out3) {
		memcpy(t_input, out2, 32);
		t_input[32] = 0x03;
		wg_blake2s_256_hmac(prk, t_input, 33, out3);
	}

	memzero_explicit(prk, sizeof(prk));
	memzero_explicit(t_input, sizeof(t_input));
}
EXPORT_SYMBOL_GPL(wg_hkdf);

/*
 * ── Curve25519 ────────────────────────────────────────────────────────
 */

int wg_curve25519(u8 out[32], const u8 scalar[32], const u8 point[32])
{
	return curve25519(out, scalar, point) ? 0 : -EINVAL;
}
EXPORT_SYMBOL_GPL(wg_curve25519);

void wg_curve25519_generate_secret(u8 secret[32])
{
	curve25519_generate_secret(secret);
}
EXPORT_SYMBOL_GPL(wg_curve25519_generate_secret);

void wg_curve25519_generate_public(u8 pub_key[32], const u8 secret[32])
{
	curve25519_generate_public(pub_key, secret);
}
EXPORT_SYMBOL_GPL(wg_curve25519_generate_public);

/*
 * ── Random ────────────────────────────────────────────────────────────
 */

void wg_get_random_bytes(u8 *buf, u32 len)
{
	get_random_bytes(buf, len);
}
EXPORT_SYMBOL_GPL(wg_get_random_bytes);
