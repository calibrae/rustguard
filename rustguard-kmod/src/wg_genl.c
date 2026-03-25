// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — Genetlink interface for wg(8) tool compatibility.
 *
 * Implements WG_CMD_SET_DEVICE and WG_CMD_GET_DEVICE so the standard
 * `wg` userspace tool can configure and query our interfaces.
 *
 * This is the most C-heavy part — genetlink is a pure C kernel API
 * with no Rust bindings. The callbacks translate genetlink attributes
 * into calls to Rust functions that modify device state.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>

/* WireGuard genetlink constants (from uapi/linux/wireguard.h). */
#define WG_GENL_NAME		"wireguard"
#define WG_GENL_VERSION		1

enum wg_cmd {
	WG_CMD_GET_DEVICE,
	WG_CMD_SET_DEVICE,
	__WG_CMD_MAX
};

enum wgdevice_attribute {
	WGDEVICE_A_UNSPEC,
	WGDEVICE_A_IFINDEX,
	WGDEVICE_A_IFNAME,
	WGDEVICE_A_PRIVATE_KEY,
	WGDEVICE_A_PUBLIC_KEY,
	WGDEVICE_A_FLAGS,
	WGDEVICE_A_LISTEN_PORT,
	WGDEVICE_A_FWMARK,
	WGDEVICE_A_PEERS,
	__WGDEVICE_A_LAST
};

enum wgpeer_attribute {
	WGPEER_A_UNSPEC,
	WGPEER_A_PUBLIC_KEY,
	WGPEER_A_PRESHARED_KEY,
	WGPEER_A_FLAGS,
	WGPEER_A_ENDPOINT,
	WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
	WGPEER_A_LAST_HANDSHAKE_TIME,
	WGPEER_A_RX_BYTES,
	WGPEER_A_TX_BYTES,
	WGPEER_A_ALLOWEDIPS,
	WGPEER_A_PROTOCOL_VERSION,
	__WGPEER_A_LAST
};

enum wgallowedip_attribute {
	WGALLOWEDIP_A_UNSPEC,
	WGALLOWEDIP_A_FAMILY,
	WGALLOWEDIP_A_IPADDR,
	WGALLOWEDIP_A_CIDR_MASK,
	__WGALLOWEDIP_A_LAST
};

/* Forward declarations — implemented in Rust. */
extern int rustguard_genl_get(void *priv_data, void *msg_buf, int buf_len);
extern int rustguard_genl_set(void *priv_data, const unsigned char *peer_pubkey,
			      unsigned int endpoint_ip, unsigned short endpoint_port,
			      const unsigned char *allowed_ip, unsigned char allowed_cidr,
			      unsigned short allowed_family);

/* Prototypes. */
int wg_genl_init(void);
void wg_genl_exit(void);

/* Stubs for now — full implementation requires parsing nested netlink attrs.
 * For initial testing, the module params work. This provides the skeleton
 * for wg(8) tool integration.
 */

static int wg_get_device(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("rustguard: genl GET_DEVICE\n");
	return 0;
}

static int wg_set_device(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("rustguard: genl SET_DEVICE\n");
	/* TODO: parse WGDEVICE_A_PRIVATE_KEY, WGDEVICE_A_LISTEN_PORT,
	 * WGDEVICE_A_PEERS with nested WGPEER_A_PUBLIC_KEY,
	 * WGPEER_A_ENDPOINT, WGPEER_A_ALLOWEDIPS, etc.
	 * Then call rustguard_genl_set to update device state. */
	return 0;
}

static const struct nla_policy wg_device_policy[__WGDEVICE_A_LAST] = {
	[WGDEVICE_A_IFINDEX] = { .type = NLA_U32 },
	[WGDEVICE_A_IFNAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[WGDEVICE_A_PRIVATE_KEY] = { .len = 32 },
	[WGDEVICE_A_PUBLIC_KEY] = { .len = 32 },
	[WGDEVICE_A_FLAGS] = { .type = NLA_U32 },
	[WGDEVICE_A_LISTEN_PORT] = { .type = NLA_U16 },
	[WGDEVICE_A_FWMARK] = { .type = NLA_U32 },
	[WGDEVICE_A_PEERS] = { .type = NLA_NESTED },
};

static const struct genl_ops wg_genl_ops[] = {
	{
		.cmd = WG_CMD_GET_DEVICE,
		.doit = wg_get_device,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = WG_CMD_SET_DEVICE,
		.doit = wg_set_device,
		.flags = GENL_UNS_ADMIN_PERM,
	},
};

static struct genl_family wg_genl_family = {
	.name = WG_GENL_NAME,
	.version = WG_GENL_VERSION,
	.maxattr = __WGDEVICE_A_LAST - 1,
	.policy = wg_device_policy,
	.module = THIS_MODULE,
	.ops = wg_genl_ops,
	.n_ops = ARRAY_SIZE(wg_genl_ops),
};

int wg_genl_init(void)
{
	return genl_register_family(&wg_genl_family);
}
EXPORT_SYMBOL_GPL(wg_genl_init);

void wg_genl_exit(void)
{
	genl_unregister_family(&wg_genl_family);
}
EXPORT_SYMBOL_GPL(wg_genl_exit);
