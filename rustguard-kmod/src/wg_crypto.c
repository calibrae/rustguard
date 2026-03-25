// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — C shim for kernel crypto.
 *
 * Uses the kernel's library crypto functions (same as kernel WireGuard).
 * Provides: ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2s, HKDF, Curve25519.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>
#include <crypto/curve25519.h>
#include <crypto/algapi.h> /* crypto_memneq */

/* ── Prototypes ────────────────────────────────────────────────────── */

int wg_chacha20poly1305_encrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
int wg_chacha20poly1305_decrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
int wg_xchacha20poly1305_encrypt(
	const u8 key[32], const u8 nonce[24], const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
int wg_xchacha20poly1305_decrypt(
	const u8 key[32], const u8 nonce[24], const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst);
void wg_blake2s_hash(const u8 *const *chunks, const u32 *chunk_lens,
	u32 num_chunks, u8 out[32]);
void wg_blake2s_256_hmac(const u8 key[32], const u8 *data, u32 data_len,
	u8 out[32]);
void wg_blake2s_256_mac(const u8 *key, u32 key_len,
	const u8 *data, u32 data_len, u8 out[32]);
void wg_hkdf(const u8 key[32], const u8 *input, u32 input_len,
	u8 out1[32], u8 out2[32], u8 out3[32]);
int wg_curve25519(u8 out[32], const u8 scalar[32], const u8 point[32]);
void wg_curve25519_generate_secret(u8 secret[32]);
void wg_curve25519_generate_public(u8 pub_key[32], const u8 secret[32]);
void wg_get_random_bytes(u8 *buf, u32 len);
int wg_crypto_init(void);
void wg_crypto_exit(void);

/* ── ChaCha20-Poly1305 ────────────────────────────────────────────── */

int wg_chacha20poly1305_encrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, nonce, key);
	return 0;
}
EXPORT_SYMBOL_GPL(wg_chacha20poly1305_encrypt);

int wg_chacha20poly1305_decrypt(
	const u8 key[32], u64 nonce, const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	if (src_len < CHACHA20POLY1305_AUTHTAG_SIZE)
		return -EINVAL;
	if (!chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, nonce, key))
		return -EBADMSG;
	return 0;
}
EXPORT_SYMBOL_GPL(wg_chacha20poly1305_decrypt);

/* ── XChaCha20-Poly1305 (for cookie encryption) ───────────────────── */

int wg_xchacha20poly1305_encrypt(
	const u8 key[32], const u8 nonce[24], const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	xchacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, nonce, key);
	return 0;
}
EXPORT_SYMBOL_GPL(wg_xchacha20poly1305_encrypt);

int wg_xchacha20poly1305_decrypt(
	const u8 key[32], const u8 nonce[24], const u8 *src, u32 src_len,
	const u8 *ad, u32 ad_len, u8 *dst)
{
	if (src_len < CHACHA20POLY1305_AUTHTAG_SIZE)
		return -EINVAL;
	if (!xchacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, nonce, key))
		return -EBADMSG;
	return 0;
}
EXPORT_SYMBOL_GPL(wg_xchacha20poly1305_decrypt);

/* ── BLAKE2s ───────────────────────────────────────────────────────── */

/*
 * Multi-buffer BLAKE2s-256 hash: H(chunk[0] || chunk[1] || ... || chunk[n-1])
 * Used throughout WireGuard for mix_hash, initial_hash, etc.
 */
void wg_blake2s_hash(const u8 *const *chunks, const u32 *chunk_lens,
	u32 num_chunks, u8 out[32])
{
	struct blake2s_state state;
	u32 i;

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	for (i = 0; i < num_chunks; i++)
		blake2s_update(&state, chunks[i], chunk_lens[i]);
	blake2s_final(&state, out);
}
EXPORT_SYMBOL_GPL(wg_blake2s_hash);

/* Keyed BLAKE2s MAC — for MAC1/MAC2. */
void wg_blake2s_256_mac(const u8 *key, u32 key_len,
	const u8 *data, u32 data_len, u8 out[32])
{
	blake2s(out, data, key, BLAKE2S_HASH_SIZE, data_len, key_len);
}
EXPORT_SYMBOL_GPL(wg_blake2s_256_mac);

/* HMAC-BLAKE2s — for HKDF. */
void wg_blake2s_256_hmac(const u8 key[32], const u8 *data, u32 data_len,
	u8 out[32])
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

/* HKDF: extract + expand to 3 outputs. out3 may be NULL. */
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

/* ── Zero-copy skb encrypt/decrypt ─────────────────────────────────── */

/*
 * Encrypt an skb's payload in-place using scatter-gather AEAD.
 * The skb must have headroom for the WireGuard header (already written)
 * and tailroom for the 16-byte AEAD tag.
 *
 * This is the same approach as kernel WireGuard (send.c:216):
 *   chacha20poly1305_encrypt_sg_inplace(sg, plaintext_len, ...)
 *
 * Returns 0 on success.
 */
int wg_encrypt_skb(struct sk_buff *skb, u32 plaintext_off, u32 plaintext_len,
		   u64 nonce, const u8 key[32]);
int wg_encrypt_skb(struct sk_buff *skb, u32 plaintext_off, u32 plaintext_len,
		   u64 nonce, const u8 key[32])
{
	struct scatterlist sg;

	/* Build SG over the plaintext + tag region of the skb.
	 * The skb was pre-allocated with room for the tag by
	 * wg_skb_prepend_header, so no cow needed. */
	sg_init_one(&sg, skb->data + plaintext_off,
		    plaintext_len + CHACHA20POLY1305_AUTHTAG_SIZE);

	if (!chacha20poly1305_encrypt_sg_inplace(&sg, plaintext_len,
						  NULL, 0, nonce, key))
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(wg_encrypt_skb);

/*
 * Decrypt an skb's payload in-place using scatter-gather AEAD.
 * The encrypted region starts at `ct_off` and is `ct_len` bytes
 * (including the 16-byte tag).
 *
 * Returns 0 on success, -EBADMSG on auth failure.
 */
/*
 * Full RX decrypt pipeline: copy skb → SG decrypt in-place → strip header → trim tag.
 * Returns a NEW skb containing just the decrypted plaintext, or NULL on failure.
 * The original skb is NOT consumed — caller must free it.
 *
 * Why all in C: sg_init_one can't handle page-boundary crossings.
 * skb_to_sgvec handles them correctly but requires careful skb manipulation
 * that's safer to do entirely in C where we can inspect the result.
 */
struct sk_buff *wg_decrypt_skb_full(struct sk_buff *skb, u32 hdr_len,
				    u64 nonce, const u8 key[32]);
struct sk_buff *wg_decrypt_skb_full(struct sk_buff *skb, u32 hdr_len,
				    u64 nonce, const u8 key[32])
{
	struct sk_buff *nskb;
	struct scatterlist sg;
	u32 ct_len;

	if (skb->len <= hdr_len + CHACHA20POLY1305_AUTHTAG_SIZE)
		return NULL;

	ct_len = skb->len - hdr_len;

	/* Make a writable linear copy. skb_copy guarantees:
	 * - Linear (no frags, data_len == 0)
	 * - Exclusive (refcount == 1, not cloned)
	 * - All data in skb->data[0..skb->len]
	 */
	nskb = skb_copy(skb, GFP_ATOMIC);
	if (!nskb)
		return NULL;

	/* Pull the WireGuard header so data starts at ciphertext. */
	skb_pull(nskb, hdr_len);

	/* Single SG entry — skb_copy guarantees linear data.
	 * No skb_cow_data needed (it crashes on some encap_rcv skb states).
	 * No skb_to_sgvec needed (data is contiguous, no frags). */
	sg_init_one(&sg, nskb->data, ct_len);

	/* Decrypt in place. */
	if (!chacha20poly1305_decrypt_sg_inplace(&sg, ct_len,
						  NULL, 0, nonce, key)) {
		kfree_skb(nskb);
		return NULL;
	}

	/* Trim the AEAD tag. */
	if (pskb_trim(nskb, ct_len - CHACHA20POLY1305_AUTHTAG_SIZE)) {
		kfree_skb(nskb);
		return NULL;
	}

	return nskb;
}
EXPORT_SYMBOL_GPL(wg_decrypt_skb_full);

/* ── Curve25519 ────────────────────────────────────────────────────── */

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
	if (!curve25519_generate_public(pub_key, secret))
		memset(pub_key, 0, 32);
}
EXPORT_SYMBOL_GPL(wg_curve25519_generate_public);

/* ── Random + Lifecycle ────────────────────────────────────────────── */

void wg_get_random_bytes(u8 *buf, u32 len)
{
	get_random_bytes(buf, len);
}
EXPORT_SYMBOL_GPL(wg_get_random_bytes);

/* ktime_get_ns / ktime_get_real_ts64 are inline — wrap for Rust FFI. */
u64 wg_ktime_get_ns(void);
u64 wg_ktime_get_ns(void) { return ktime_get_ns(); }
EXPORT_SYMBOL_GPL(wg_ktime_get_ns);

void wg_ktime_get_real(s64 *secs, s64 *nsecs);
void wg_ktime_get_real(s64 *secs, s64 *nsecs)
{
	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
	*secs = ts.tv_sec;
	*nsecs = ts.tv_nsec;
}
EXPORT_SYMBOL_GPL(wg_ktime_get_real);

/* ── Secure memory operations ──────────────────────────────────────── */

/*
 * wg_memzero: Guaranteed-not-optimized-away memset for key material.
 * Wraps memzero_explicit which uses barrier() to prevent dead-store
 * elimination. Called from Rust via FFI to zeroize secrets.
 */
void wg_memzero(void *ptr, size_t len);
void wg_memzero(void *ptr, size_t len)
{
	memzero_explicit(ptr, len);
}
EXPORT_SYMBOL_GPL(wg_memzero);

/*
 * wg_crypto_memneq: Constant-time memory comparison.
 * Wraps crypto_memneq which the compiler cannot optimize into
 * a short-circuit comparison. Returns 0 if equal, nonzero otherwise.
 */
int wg_crypto_memneq(const void *a, const void *b, size_t len);
int wg_crypto_memneq(const void *a, const void *b, size_t len)
{
	return crypto_memneq(a, b, len);
}
EXPORT_SYMBOL_GPL(wg_crypto_memneq);

int wg_crypto_init(void) { return 0; }
EXPORT_SYMBOL_GPL(wg_crypto_init);

void wg_crypto_exit(void) {}
EXPORT_SYMBOL_GPL(wg_crypto_exit);
