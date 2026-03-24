// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — C shim for networking primitives.
 *
 * The kernel's Rust bindings (6.12) don't expose net_device, sk_buff,
 * or the crypto API. This thin C layer handles device registration and
 * provides callback hooks that the Rust module implements.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>

#define WG_MTU 1420
#define WG_NETDEV_NAME "wg%d"

/*
 * Module parameters for test configuration.
 * In production these come from genetlink (wg tool), but for testing
 * we hardcode a single peer via insmod params.
 *
 * Usage:
 *   insmod rustguard.ko peer_ip=0xC0A86302 peer_port=51820 role=0
 *   (peer_ip in hex host-order: 192.168.99.2 = 0xC0A86302)
 */
static unsigned int peer_ip = 0;
module_param(peer_ip, uint, 0644);
MODULE_PARM_DESC(peer_ip, "Peer endpoint IPv4 (host byte order, hex)");

static unsigned int peer_port = 51820;
module_param(peer_port, uint, 0644);
MODULE_PARM_DESC(peer_port, "Peer endpoint UDP port");

static unsigned int role = 0;
module_param(role, uint, 0644);
MODULE_PARM_DESC(role, "0=initiator (send=key_a,recv=key_b), 1=responder (reversed)");

/* Prototypes. */
unsigned int wg_param_peer_ip(void);
unsigned int wg_param_peer_port(void);
unsigned int wg_param_role(void);

/* Exported to Rust. */
unsigned int wg_param_peer_ip(void) { return peer_ip; }
EXPORT_SYMBOL_GPL(wg_param_peer_ip);

unsigned int wg_param_peer_port(void) { return peer_port; }
EXPORT_SYMBOL_GPL(wg_param_peer_port);

unsigned int wg_param_role(void) { return role; }
EXPORT_SYMBOL_GPL(wg_param_role);

/* Prototypes for functions exported to Rust. */
struct net_device *wg_create_device(void *rust_priv);
void wg_destroy_device(struct net_device *dev);
void wg_net_rx(struct net_device *dev, struct sk_buff *skb);
struct sk_buff *wg_alloc_skb(unsigned int len);
void wg_skb_data(struct sk_buff *skb, unsigned char **data, unsigned int *len);
void wg_kfree_skb(struct sk_buff *skb);
void wg_tx_stats(struct net_device *dev, unsigned int bytes);

/* Forward declarations — implemented in Rust. */
extern netdev_tx_t rustguard_xmit(struct sk_buff *skb, void *priv);
extern void rustguard_dev_uninit(void *priv);

/* Per-device private data — pointer to Rust-side state. */
struct wg_device {
	void *rust_priv;
};

/* ── net_device_ops callbacks ──────────────────────────────────────── */

static netdev_tx_t wg_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);

	if (unlikely(!wg->rust_priv)) {
		kfree_skb(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	return rustguard_xmit(skb, wg->rust_priv);
}

static int wg_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int wg_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static const struct net_device_ops wg_netdev_ops = {
	.ndo_open       = wg_open,
	.ndo_stop       = wg_stop,
	.ndo_start_xmit = wg_xmit,
};

/* ── Device setup ──────────────────────────────────────────────────── */

static void wg_setup(struct net_device *dev)
{
	dev->netdev_ops = &wg_netdev_ops;

	/* WireGuard is a point-to-point tunnel, not Ethernet. */
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->mtu = WG_MTU;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = 0;
	dev->needed_tailroom = 0;
}

/* ── Exported to Rust ──────────────────────────────────────────────── */

struct net_device *wg_create_device(void *rust_priv)
{
	struct net_device *dev;
	struct wg_device *wg;
	int ret;

	dev = alloc_netdev(sizeof(struct wg_device), WG_NETDEV_NAME,
			   NET_NAME_UNKNOWN, wg_setup);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	wg = netdev_priv(dev);
	wg->rust_priv = rust_priv;

	ret = register_netdev(dev);
	if (ret) {
		free_netdev(dev);
		return ERR_PTR(ret);
	}

	return dev;
}
EXPORT_SYMBOL_GPL(wg_create_device);

void wg_destroy_device(struct net_device *dev)
{
	if (!dev)
		return;
	unregister_netdev(dev);
	free_netdev(dev);
}
EXPORT_SYMBOL_GPL(wg_destroy_device);

void wg_net_rx(struct net_device *dev, struct sk_buff *skb)
{
	unsigned char ip_version;

	skb->dev = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_reset_network_header(skb);

	/* Determine protocol from IP version nibble. */
	if (skb->len >= 1) {
		ip_version = skb->data[0] >> 4;
		if (ip_version == 4)
			skb->protocol = htons(ETH_P_IP);
		else if (ip_version == 6)
			skb->protocol = htons(ETH_P_IPV6);
		else
			skb->protocol = 0;
	}

	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;

	netif_rx(skb);
}
EXPORT_SYMBOL_GPL(wg_net_rx);

struct sk_buff *wg_alloc_skb(unsigned int len)
{
	return alloc_skb(len, GFP_ATOMIC);
}
EXPORT_SYMBOL_GPL(wg_alloc_skb);

void wg_skb_data(struct sk_buff *skb, unsigned char **data, unsigned int *len)
{
	*data = skb->data;
	*len = skb->len;
}
EXPORT_SYMBOL_GPL(wg_skb_data);

void wg_kfree_skb(struct sk_buff *skb)
{
	kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(wg_kfree_skb);

void wg_tx_stats(struct net_device *dev, unsigned int bytes)
{
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += bytes;
}
EXPORT_SYMBOL_GPL(wg_tx_stats);
