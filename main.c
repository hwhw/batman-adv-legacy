/* Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/crc32c.h>
#include <linux/highmem.h>
#include "main.h"
#include "sysfs.h"
#include "debugfs.h"
#include "routing.h"
#include "send.h"
#include "originator.h"
#include "soft-interface.h"
#include "icmp_socket.h"
#include "translation-table.h"
#include "hard-interface.h"
#include "gateway_client.h"
#include "bridge_loop_avoidance.h"
#include "distributed-arp-table.h"
#include "hash.h"
#include "bat_algo.h"
#include "network-coding.h"


/* List manipulations on hardif_list have to be rtnl_lock()'ed,
 * list traversals just rcu-locked
 */
struct list_head batadv14_hardif_list;
static int (*batadv14_rx_handler[256])(struct sk_buff *,
				     struct batadv14_hard_iface *);
char batadv14_routing_algo[20] = "BATMAN_IV";
static struct hlist_head batadv14_algo_list;

unsigned char batadv14_broadcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct workqueue_struct *batadv14_event_workqueue;

static void batadv14_recv_handler_init(void);

static int __init batadv14_init(void)
{
	INIT_LIST_HEAD(&batadv14_hardif_list);
	INIT_HLIST_HEAD(&batadv14_algo_list);

	batadv14_recv_handler_init();

	batadv14_iv_init();
	batadv14_nc_init();

	batadv14_event_workqueue = create_singlethread_workqueue("bat_events");

	if (!batadv14_event_workqueue)
		return -ENOMEM;

	batadv14_socket_init();
	batadv14_debugfs_init();

	register_netdevice_notifier(&batadv14_hard_if_notifier);
	rtnl_link_register(&batadv14_link_ops);

	pr_info("B.A.T.M.A.N. advanced %s (compatibility version %i) loaded\n",
		BATADV_SOURCE_VERSION, BATADV_COMPAT_VERSION);

	return 0;
}

static void __exit batadv14_exit(void)
{
	batadv14_debugfs_destroy();
	rtnl_link_unregister(&batadv14_link_ops);
	unregister_netdevice_notifier(&batadv14_hard_if_notifier);
	batadv14_hardif_remove_interfaces();

	flush_workqueue(batadv14_event_workqueue);
	destroy_workqueue(batadv14_event_workqueue);
	batadv14_event_workqueue = NULL;

	rcu_barrier();
}

int batadv14_mesh_init(struct net_device *soft_iface)
{
	struct batadv14_priv *bat_priv = netdev_priv(soft_iface);
	int ret;

	spin_lock_init(&bat_priv->forw_bat_list_lock);
	spin_lock_init(&bat_priv->forw_bcast_list_lock);
	spin_lock_init(&bat_priv->tt.changes_list_lock);
	spin_lock_init(&bat_priv->tt.req_list_lock);
	spin_lock_init(&bat_priv->tt.roam_list_lock);
	spin_lock_init(&bat_priv->tt.last_changeset_lock);
	spin_lock_init(&bat_priv->gw.list_lock);

	INIT_HLIST_HEAD(&bat_priv->forw_bat_list);
	INIT_HLIST_HEAD(&bat_priv->forw_bcast_list);
	INIT_HLIST_HEAD(&bat_priv->gw.list);
	INIT_LIST_HEAD(&bat_priv->tt.changes_list);
	INIT_LIST_HEAD(&bat_priv->tt.req_list);
	INIT_LIST_HEAD(&bat_priv->tt.roam_list);

	ret = batadv14_originator_init(bat_priv);
	if (ret < 0)
		goto err;

	ret = batadv14_tt_init(bat_priv);
	if (ret < 0)
		goto err;

	batadv14_tt_local_add(soft_iface, soft_iface->dev_addr,
			    BATADV_NULL_IFINDEX);

	ret = batadv14_bla_init(bat_priv);
	if (ret < 0)
		goto err;

	ret = batadv14_dat_init(bat_priv);
	if (ret < 0)
		goto err;

	ret = batadv14_nc_mesh_init(bat_priv);
	if (ret < 0)
		goto err;

	atomic_set(&bat_priv->gw.reselect, 0);
	atomic_set(&bat_priv->mesh_state, BATADV_MESH_ACTIVE);

	return 0;

err:
	batadv14_mesh_free(soft_iface);
	return ret;
}

void batadv14_mesh_free(struct net_device *soft_iface)
{
	struct batadv14_priv *bat_priv = netdev_priv(soft_iface);

	atomic_set(&bat_priv->mesh_state, BATADV_MESH_DEACTIVATING);

	batadv14_purge_outstanding_packets(bat_priv, NULL);

	batadv14_gw_node_purge(bat_priv);
	batadv14_nc_mesh_free(bat_priv);
	batadv14_dat_free(bat_priv);
	batadv14_bla_free(bat_priv);

	/* Free the TT and the originator tables only after having terminated
	 * all the other depending components which may use these structures for
	 * their purposes.
	 */
	batadv14_tt_free(bat_priv);

	/* Since the originator table clean up routine is accessing the TT
	 * tables as well, it has to be invoked after the TT tables have been
	 * freed and marked as empty. This ensures that no cleanup RCU callbacks
	 * accessing the TT data are scheduled for later execution.
	 */
	batadv14_originator_free(bat_priv);

	free_percpu(bat_priv->bat_counters);
	bat_priv->bat_counters = NULL;

	atomic_set(&bat_priv->mesh_state, BATADV_MESH_INACTIVE);
}

/**
 * batadv14_is_my_mac - check if the given mac address belongs to any of the real
 * interfaces in the current mesh
 * @bat_priv: the bat priv with all the soft interface information
 * @addr: the address to check
 */
int batadv14_is_my_mac(struct batadv14_priv *bat_priv, const uint8_t *addr)
{
	const struct batadv14_hard_iface *hard_iface;

	rcu_read_lock();
	list_for_each_entry_rcu(hard_iface, &batadv14_hardif_list, list) {
		if (hard_iface->if_status != BATADV_IF_ACTIVE)
			continue;

		if (hard_iface->soft_iface != bat_priv->soft_iface)
			continue;

		if (batadv14_compare_eth(hard_iface->net_dev->dev_addr, addr)) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
}

/**
 * batadv14_seq_print_text_primary_if_get - called from debugfs table printing
 *  function that requires the primary interface
 * @seq: debugfs table seq_file struct
 *
 * Returns primary interface if found or NULL otherwise.
 */
struct batadv14_hard_iface *
batadv14_seq_print_text_primary_if_get(struct seq_file *seq)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct batadv14_priv *bat_priv = netdev_priv(net_dev);
	struct batadv14_hard_iface *primary_if;

	primary_if = batadv14_primary_if_get_selected(bat_priv);

	if (!primary_if) {
		seq_printf(seq,
			   "BATMAN mesh %s disabled - please specify interfaces to enable it\n",
			   net_dev->name);
		goto out;
	}

	if (primary_if->if_status == BATADV_IF_ACTIVE)
		goto out;

	seq_printf(seq,
		   "BATMAN mesh %s disabled - primary interface not active\n",
		   net_dev->name);
	batadv14_hardif_free_ref(primary_if);
	primary_if = NULL;

out:
	return primary_if;
}

static int batadv14_recv_unhandled_packet(struct sk_buff *skb,
					struct batadv14_hard_iface *recv_if)
{
	return NET_RX_DROP;
}

/* incoming packets with the batman ethertype received on any active hard
 * interface
 */
int batadv14_batman_skb_recv(struct sk_buff *skb, struct net_device *dev,
			   struct packet_type *ptype,
			   struct net_device *orig_dev)
{
	struct batadv14_priv *bat_priv;
	struct batadv14_ogm_packet *batadv14_ogm_packet;
	struct batadv14_hard_iface *hard_iface;
	uint8_t idx;
	int ret;

	hard_iface = container_of(ptype, struct batadv14_hard_iface,
				  batman_adv14_ptype);
	skb = skb_share_check(skb, GFP_ATOMIC);

	/* skb was released by skb_share_check() */
	if (!skb)
		goto err_out;

	/* packet should hold at least type and version */
	if (unlikely(!pskb_may_pull(skb, 2)))
		goto err_free;

	/* expect a valid ethernet header here. */
	if (unlikely(skb->mac_len != ETH_HLEN || !skb_mac_header(skb)))
		goto err_free;

	if (!hard_iface->soft_iface)
		goto err_free;

	bat_priv = netdev_priv(hard_iface->soft_iface);

	if (atomic_read(&bat_priv->mesh_state) != BATADV_MESH_ACTIVE)
		goto err_free;

	/* discard frames on not active interfaces */
	if (hard_iface->if_status != BATADV_IF_ACTIVE)
		goto err_free;

	batadv14_ogm_packet = (struct batadv14_ogm_packet *)skb->data;

	if (batadv14_ogm_packet->header.version != BATADV_COMPAT_VERSION) {
		batadv14_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Drop packet: incompatible batman version (%i)\n",
			   batadv14_ogm_packet->header.version);
		goto err_free;
	}

	/* all receive handlers return whether they received or reused
	 * the supplied skb. if not, we have to free the skb.
	 */
	idx = batadv14_ogm_packet->header.packet_type;
	ret = (*batadv14_rx_handler[idx])(skb, hard_iface);

	if (ret == NET_RX_DROP)
		kfree_skb(skb);

	/* return NET_RX_SUCCESS in any case as we
	 * most probably dropped the packet for
	 * routing-logical reasons.
	 */
	return NET_RX_SUCCESS;

err_free:
	kfree_skb(skb);
err_out:
	return NET_RX_DROP;
}

static void batadv14_recv_handler_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(batadv14_rx_handler); i++)
		batadv14_rx_handler[i] = batadv14_recv_unhandled_packet;

	/* batman icmp packet */
	batadv14_rx_handler[BATADV_ICMP] = batadv14_recv_icmp_packet;
	/* unicast with 4 addresses packet */
	batadv14_rx_handler[BATADV_UNICAST_4ADDR] = batadv14_recv_unicast_packet;
	/* unicast packet */
	batadv14_rx_handler[BATADV_UNICAST] = batadv14_recv_unicast_packet;
	/* fragmented unicast packet */
	batadv14_rx_handler[BATADV_UNICAST_FRAG] = batadv14_recv_ucast_frag_packet;
	/* broadcast packet */
	batadv14_rx_handler[BATADV_BCAST] = batadv14_recv_bcast_packet;
	/* vis packet */
	batadv14_rx_handler[BATADV_VIS] = batadv14_recv_vis_packet;
	/* Translation table query (request or response) */
	batadv14_rx_handler[BATADV_TT_QUERY] = batadv14_recv_tt_query;
	/* Roaming advertisement */
	batadv14_rx_handler[BATADV_ROAM_ADV] = batadv14_recv_roam_adv;
}

int
batadv14_recv_handler_register(uint8_t packet_type,
			     int (*recv_handler)(struct sk_buff *,
						 struct batadv14_hard_iface *))
{
	if (batadv14_rx_handler[packet_type] != &batadv14_recv_unhandled_packet)
		return -EBUSY;

	batadv14_rx_handler[packet_type] = recv_handler;
	return 0;
}

void batadv14_recv_handler_unregister(uint8_t packet_type)
{
	batadv14_rx_handler[packet_type] = batadv14_recv_unhandled_packet;
}

static struct batadv14_algo_ops *batadv14_algo_get(char *name)
{
	struct batadv14_algo_ops *bat_algo_ops = NULL, *bat_algo_ops_tmp;

	hlist_for_each_entry(bat_algo_ops_tmp, &batadv14_algo_list, list) {
		if (strcmp(bat_algo_ops_tmp->name, name) != 0)
			continue;

		bat_algo_ops = bat_algo_ops_tmp;
		break;
	}

	return bat_algo_ops;
}

int batadv14_algo_register(struct batadv14_algo_ops *bat_algo_ops)
{
	struct batadv14_algo_ops *bat_algo_ops_tmp;
	int ret;

	bat_algo_ops_tmp = batadv14_algo_get(bat_algo_ops->name);
	if (bat_algo_ops_tmp) {
		pr_info("Trying to register already registered routing algorithm: %s\n",
			bat_algo_ops->name);
		ret = -EEXIST;
		goto out;
	}

	/* all algorithms must implement all ops (for now) */
	if (!bat_algo_ops->bat_iface_enable ||
	    !bat_algo_ops->bat_iface_disable ||
	    !bat_algo_ops->bat_iface_update_mac ||
	    !bat_algo_ops->bat_primary_iface_set ||
	    !bat_algo_ops->bat_ogm_schedule ||
	    !bat_algo_ops->bat_ogm_emit) {
		pr_info("Routing algo '%s' does not implement required ops\n",
			bat_algo_ops->name);
		ret = -EINVAL;
		goto out;
	}

	INIT_HLIST_NODE(&bat_algo_ops->list);
	hlist_add_head(&bat_algo_ops->list, &batadv14_algo_list);
	ret = 0;

out:
	return ret;
}

int batadv14_algo_select(struct batadv14_priv *bat_priv, char *name)
{
	struct batadv14_algo_ops *bat_algo_ops;
	int ret = -EINVAL;

	bat_algo_ops = batadv14_algo_get(name);
	if (!bat_algo_ops)
		goto out;

	bat_priv->bat_algo_ops = bat_algo_ops;
	ret = 0;

out:
	return ret;
}

int batadv14_algo_seq_print_text(struct seq_file *seq, void *offset)
{
	struct batadv14_algo_ops *bat_algo_ops;

	seq_puts(seq, "Available routing algorithms:\n");

	hlist_for_each_entry(bat_algo_ops, &batadv14_algo_list, list) {
		seq_printf(seq, "%s\n", bat_algo_ops->name);
	}

	return 0;
}

/**
 * batadv14_skb_crc32 - calculate CRC32 of the whole packet and skip bytes in
 *  the header
 * @skb: skb pointing to fragmented socket buffers
 * @payload_ptr: Pointer to position inside the head buffer of the skb
 *  marking the start of the data to be CRC'ed
 *
 * payload_ptr must always point to an address in the skb head buffer and not to
 * a fragment.
 */
__be32 batadv14_skb_crc32(struct sk_buff *skb, u8 *payload_ptr)
{
	u32 crc = 0;
	unsigned int from;
	unsigned int to = skb->len;
	struct skb_seq_state st;
	const u8 *data;
	unsigned int len;
	unsigned int consumed = 0;

	from = (unsigned int)(payload_ptr - skb->data);

	skb_prepare_seq_read(skb, from, to, &st);
	while ((len = skb_seq_read(consumed, &data, &st)) != 0) {
		crc = crc32c(crc, data, len);
		consumed += len;
	}

	return htonl(crc);
}

static int batadv14_param_set_ra(const char *val, const struct kernel_param *kp)
{
	struct batadv14_algo_ops *bat_algo_ops;
	char *algo_name = (char *)val;
	size_t name_len = strlen(algo_name);

	if (name_len > 0 && algo_name[name_len - 1] == '\n')
		algo_name[name_len - 1] = '\0';

	bat_algo_ops = batadv14_algo_get(algo_name);
	if (!bat_algo_ops) {
		pr_err("Routing algorithm '%s' is not supported\n", algo_name);
		return -EINVAL;
	}

	return param_set_copystring(algo_name, kp);
}

static const struct kernel_param_ops batadv14_param_ops_ra = {
	.set = batadv14_param_set_ra,
	.get = param_get_string,
};

static struct kparam_string batadv14_param_string_ra = {
	.maxlen = sizeof(batadv14_routing_algo),
	.string = batadv14_routing_algo,
};

module_param_cb(routing_algo, &batadv14_param_ops_ra, &batadv14_param_string_ra,
		0644);
module_init(batadv14_init);
module_exit(batadv14_exit);

MODULE_LICENSE("GPL");

MODULE_AUTHOR(BATADV_DRIVER_AUTHOR);
MODULE_DESCRIPTION(BATADV_DRIVER_DESC);
MODULE_SUPPORTED_DEVICE(BATADV_DRIVER_DEVICE);
MODULE_VERSION(BATADV_SOURCE_VERSION);
