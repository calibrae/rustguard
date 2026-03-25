// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — Crypto workqueue for encrypt/decrypt in process context.
 *
 * ndo_start_xmit runs in softirq — can't use kernel_fpu_begin() there.
 * The SG chacha20poly1305 path needs FPU (AVX2/AVX-512). So we queue
 * packets to a per-CPU workqueue that runs in process context, same
 * as kernel WireGuard (send.c / receive.c).
 *
 * This also enables parallel crypto across CPUs — the single biggest
 * performance win available.
 */

#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <crypto/chacha20poly1305.h>

#define WG_HEADER_SIZE 16

/* Forward declarations — implemented in Rust / wg_net.c. */
extern void wg_net_rx(struct net_device *dev, struct sk_buff *skb);
extern void wg_tx_stats(struct net_device *dev, unsigned int bytes);

/* Prototypes. */
int wg_queue_init(void);
void wg_queue_destroy(void);
int wg_queue_encrypt(struct sk_buff *skb, u32 plaintext_off, u32 plaintext_len,
		     u64 nonce, const u8 key[32], void *sock, u32 dst_ip,
		     u16 dst_port, struct net_device *dev);
int wg_queue_decrypt(struct sk_buff *skb, u32 hdr_len, u64 nonce,
		     const u8 key[32], struct net_device *dev);

/* ── Encrypt queue entry ───────────────────────────────────────────── */

struct wg_encrypt_work {
	struct work_struct work;
	struct sk_buff *skb;
	u32 plaintext_off;
	u32 plaintext_len;
	u64 nonce;
	u8 key[32];
	void *sock;        /* struct socket * */
	u32 dst_ip;
	u16 dst_port;
	struct net_device *dev;
};

/* ── Decrypt queue entry ───────────────────────────────────────────── */

struct wg_decrypt_work {
	struct work_struct work;
	struct sk_buff *skb;
	u32 hdr_len;
	u64 nonce;
	u8 key[32];
	struct net_device *dev;
};

static struct workqueue_struct *wg_crypt_wq;

/* ── Encrypt worker (process context — FPU available) ──────────────── */

static void wg_encrypt_worker(struct work_struct *work)
{
	struct wg_encrypt_work *w = container_of(work, struct wg_encrypt_work, work);
	struct scatterlist sg;
	u8 *pt = w->skb->data + w->plaintext_off;
	struct msghdr msg = {};
	struct kvec iov;
	struct sockaddr_in dst;

	/* SG encrypt in-place — safe in process context. */
	sg_init_one(&sg, pt, w->plaintext_len + CHACHA20POLY1305_AUTHTAG_SIZE);
	chacha20poly1305_encrypt_sg_inplace(&sg, w->plaintext_len,
					    NULL, 0, w->nonce, w->key);

	/* Send via UDP. */
	dst.sin_family = AF_INET;
	dst.sin_port = htons(w->dst_port);
	dst.sin_addr.s_addr = htonl(w->dst_ip);
	msg.msg_name = &dst;
	msg.msg_namelen = sizeof(dst);
	msg.msg_flags = MSG_DONTWAIT;
	iov.iov_base = w->skb->data;
	iov.iov_len = w->skb->len;

	kernel_sendmsg((struct socket *)w->sock, &msg, &iov, 1, w->skb->len);

	wg_tx_stats(w->dev, w->plaintext_len);
	kfree_skb(w->skb);
	memzero_explicit(w->key, 32);
	kfree(w);
}

/* ── Decrypt worker (process context — FPU available) ──────────────── */

static void wg_decrypt_worker(struct work_struct *work)
{
	struct wg_decrypt_work *w = container_of(work, struct wg_decrypt_work, work);
	struct scatterlist sg;
	struct sk_buff *nskb;
	u32 ct_len, pt_len;
	u8 *ct_data;

	ct_len = w->skb->len - w->hdr_len;
	pt_len = ct_len - CHACHA20POLY1305_AUTHTAG_SIZE;
	ct_data = w->skb->data + w->hdr_len;

	/* Decrypt to a fresh skb (input may be cloned/shared). */
	nskb = alloc_skb(pt_len, GFP_KERNEL); /* GFP_KERNEL — we can sleep! */
	if (!nskb)
		goto out;

	if (!chacha20poly1305_decrypt(skb_put(nskb, pt_len), ct_data,
				      ct_len, NULL, 0, w->nonce, w->key)) {
		kfree_skb(nskb);
		goto out;
	}

	wg_net_rx(w->dev, nskb);

out:
	kfree_skb(w->skb);
	memzero_explicit(w->key, 32);
	kfree(w);
}

/* ── Public API ────────────────────────────────────────────────────── */

int wg_queue_encrypt(struct sk_buff *skb, u32 plaintext_off, u32 plaintext_len,
		     u64 nonce, const u8 key[32], void *sock, u32 dst_ip,
		     u16 dst_port, struct net_device *dev)
{
	struct wg_encrypt_work *w;

	w = kmalloc(sizeof(*w), GFP_ATOMIC);
	if (!w)
		return -ENOMEM;

	INIT_WORK(&w->work, wg_encrypt_worker);
	w->skb = skb;
	w->plaintext_off = plaintext_off;
	w->plaintext_len = plaintext_len;
	w->nonce = nonce;
	memcpy(w->key, key, 32);
	w->sock = sock;
	w->dst_ip = dst_ip;
	w->dst_port = dst_port;
	w->dev = dev;

	queue_work(wg_crypt_wq, &w->work);
	return 0;
}
EXPORT_SYMBOL_GPL(wg_queue_encrypt);

int wg_queue_decrypt(struct sk_buff *skb, u32 hdr_len, u64 nonce,
		     const u8 key[32], struct net_device *dev)
{
	struct wg_decrypt_work *w;

	w = kmalloc(sizeof(*w), GFP_ATOMIC);
	if (!w)
		return -ENOMEM;

	INIT_WORK(&w->work, wg_decrypt_worker);
	w->skb = skb;
	w->hdr_len = hdr_len;
	w->nonce = nonce;
	memcpy(w->key, key, 32);
	w->dev = dev;

	queue_work(wg_crypt_wq, &w->work);
	return 0;
}
EXPORT_SYMBOL_GPL(wg_queue_decrypt);

int wg_queue_init(void)
{
	/* Unbound workqueue — kernel schedules workers across all CPUs. */
	wg_crypt_wq = alloc_workqueue("rustguard_crypt",
				      WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_HIGHPRI,
				      0);
	if (!wg_crypt_wq)
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL_GPL(wg_queue_init);

void wg_queue_destroy(void)
{
	if (wg_crypt_wq) {
		flush_workqueue(wg_crypt_wq);
		destroy_workqueue(wg_crypt_wq);
		wg_crypt_wq = NULL;
	}
}
EXPORT_SYMBOL_GPL(wg_queue_destroy);
