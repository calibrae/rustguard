// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — C shim for kernel UDP socket.
 *
 * Creates a kernel-space UDP socket for WireGuard packet I/O.
 * The encap_rcv callback fires when a UDP packet arrives — it calls
 * into Rust for decryption and routing.
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

/* Prototypes. */
struct socket *wg_socket_create(u16 port, void *rust_priv);
void wg_socket_destroy(struct socket *sock);
int wg_socket_send(struct socket *sock, const u8 *data, u32 len,
	u32 dst_ip, u16 dst_port);
void wg_skb_pull(struct sk_buff *skb, u32 len);
u32 wg_skb_len(struct sk_buff *skb);
u8 *wg_skb_data_ptr(struct sk_buff *skb);

/* Forward declaration — implemented in Rust.
 * src_ip: source IPv4 in host byte order.
 * src_port: source port in host byte order.
 */
extern int rustguard_rx(struct sk_buff *skb, void *rust_priv,
			unsigned int src_ip, unsigned short src_port);

/*
 * UDP encap_rcv callback — called by the kernel when a UDP packet
 * arrives on our socket. This is the zero-copy RX path.
 */
static int wg_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	void *rust_priv = sk->sk_user_data;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned int src_ip = 0;
	unsigned short src_port = 0;

	if (!rust_priv) {
		kfree_skb(skb);
		return 0;
	}

	/* Extract source IP:port BEFORE stripping headers.
	 * Needed for endpoint roaming — reply to where the packet came from,
	 * not where we think the peer is. */
	iph = ip_hdr(skb);
	if (iph)
		src_ip = ntohl(iph->saddr);

	udph = udp_hdr(skb);
	if (udph)
		src_port = ntohs(udph->source);

	/* Strip the UDP header — we want the WireGuard payload. */
	__skb_pull(skb, sizeof(struct udphdr));

	/* Ensure the skb data is linear AND writable.
	 * skb_linearize handles fragments but the skb may still be cloned
	 * (shared refcount). pskb_expand_head with 0 headroom forces an
	 * unclone — the data becomes exclusively ours for in-place decrypt. */
	if (skb_linearize(skb) ||
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC)) {
		kfree_skb(skb);
		return 0;
	}

	return rustguard_rx(skb, rust_priv, src_ip, src_port);
}

/*
 * Create a kernel UDP socket bound to the given port.
 * rust_priv is stored as sk_user_data for the encap callback.
 */
struct socket *wg_socket_create(u16 port, void *rust_priv)
{
	struct socket *sock = NULL;
	struct sockaddr_in addr;
	int ret;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret < 0)
		return ERR_PTR(ret);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		sock_release(sock);
		return ERR_PTR(ret);
	}

	/* Set up UDP encapsulation receive callback. */
	rcu_read_lock();
	udp_sk(sock->sk)->encap_type = UDP_ENCAP_ESPINUDP;
	udp_sk(sock->sk)->encap_rcv = wg_udp_encap_recv;
	sock->sk->sk_user_data = rust_priv;
	rcu_read_unlock();

	udp_encap_enable();

	return sock;
}
EXPORT_SYMBOL_GPL(wg_socket_create);

void wg_socket_destroy(struct socket *sock)
{
	if (!sock)
		return;
	sock_release(sock);
}
EXPORT_SYMBOL_GPL(wg_socket_destroy);

/*
 * Send encrypted data to a peer via UDP.
 * For now, IPv4 only. Returns 0 on success.
 */
int wg_socket_send(struct socket *sock, const u8 *data, u32 len,
	u32 dst_ip, u16 dst_port)
{
	struct msghdr msg = {};
	struct kvec iov;
	struct sockaddr_in dst;

	dst.sin_family = AF_INET;
	dst.sin_port = htons(dst_port);
	dst.sin_addr.s_addr = htonl(dst_ip);

	msg.msg_name = &dst;
	msg.msg_namelen = sizeof(dst);
	msg.msg_flags = MSG_DONTWAIT;

	iov.iov_base = (void *)data;
	iov.iov_len = len;

	return kernel_sendmsg(sock, &msg, &iov, 1, len);
}
EXPORT_SYMBOL_GPL(wg_socket_send);

/*
 * skb helpers for Rust — pull bytes, get length, get data pointer.
 */
void wg_skb_pull(struct sk_buff *skb, u32 len)
{
	skb_pull(skb, len);
}
EXPORT_SYMBOL_GPL(wg_skb_pull);

u32 wg_skb_len(struct sk_buff *skb)
{
	return skb->len;
}
EXPORT_SYMBOL_GPL(wg_skb_len);

u8 *wg_skb_data_ptr(struct sk_buff *skb)
{
	return skb->data;
}
EXPORT_SYMBOL_GPL(wg_skb_data_ptr);

void wg_skb_trim(struct sk_buff *skb, unsigned int len);
void wg_skb_trim(struct sk_buff *skb, unsigned int len)
{
	skb_trim(skb, len);
}
EXPORT_SYMBOL_GPL(wg_skb_trim);
