/* Copyright (C) 2011-2013 B.A.T.M.A.N. contributors:
 *
 * Antonio Quartulli
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

#ifndef _NET_BATMAN_ADV14_ARP_H_
#define _NET_BATMAN_ADV14_ARP_H_

#ifdef CONFIG_BATMAN_ADV14_DAT

#include "types.h"
#include "originator.h"

#include <linux/if_arp.h>

#define BATADV_DAT_ADDR_MAX ((batadv14_dat_addr_t)~(batadv14_dat_addr_t)0)

bool batadv14_dat_snoop_outgoing_arp_request(struct batadv14_priv *bat_priv,
					   struct sk_buff *skb);
bool batadv14_dat_snoop_incoming_arp_request(struct batadv14_priv *bat_priv,
					   struct sk_buff *skb, int hdr_size);
void batadv14_dat_snoop_outgoing_arp_reply(struct batadv14_priv *bat_priv,
					 struct sk_buff *skb);
bool batadv14_dat_snoop_incoming_arp_reply(struct batadv14_priv *bat_priv,
					 struct sk_buff *skb, int hdr_size);
bool batadv14_dat_drop_broadcast_packet(struct batadv14_priv *bat_priv,
				      struct batadv14_forw_packet *forw_packet);

/**
 * batadv14_dat_init_orig_node_addr - assign a DAT address to the orig_node
 * @orig_node: the node to assign the DAT address to
 */
static inline void
batadv14_dat_init_orig_node_addr(struct batadv14_orig_node *orig_node)
{
	uint32_t addr;

	addr = batadv14_choose_orig(orig_node->orig, BATADV_DAT_ADDR_MAX);
	orig_node->dat_addr = (batadv14_dat_addr_t)addr;
}

/**
 * batadv14_dat_init_own_addr - assign a DAT address to the node itself
 * @bat_priv: the bat priv with all the soft interface information
 * @primary_if: a pointer to the primary interface
 */
static inline void
batadv14_dat_init_own_addr(struct batadv14_priv *bat_priv,
			 struct batadv14_hard_iface *primary_if)
{
	uint32_t addr;

	addr = batadv14_choose_orig(primary_if->net_dev->dev_addr,
				  BATADV_DAT_ADDR_MAX);

	bat_priv->dat.addr = (batadv14_dat_addr_t)addr;
}

int batadv14_dat_init(struct batadv14_priv *bat_priv);
void batadv14_dat_free(struct batadv14_priv *bat_priv);
int batadv14_dat_cache_seq_print_text(struct seq_file *seq, void *offset);

/**
 * batadv14_dat_inc_counter - increment the correct DAT packet counter
 * @bat_priv: the bat priv with all the soft interface information
 * @subtype: the 4addr subtype of the packet to be counted
 *
 * Updates the ethtool statistics for the received packet if it is a DAT subtype
 */
static inline void batadv14_dat_inc_counter(struct batadv14_priv *bat_priv,
					  uint8_t subtype)
{
	switch (subtype) {
	case BATADV_P_DAT_DHT_GET:
		batadv14_inc_counter(bat_priv,
				   BATADV_CNT_DAT_GET_RX);
		break;
	case BATADV_P_DAT_DHT_PUT:
		batadv14_inc_counter(bat_priv,
				   BATADV_CNT_DAT_PUT_RX);
		break;
	}
}

#else

static inline bool
batadv14_dat_snoop_outgoing_arp_request(struct batadv14_priv *bat_priv,
				      struct sk_buff *skb)
{
	return false;
}

static inline bool
batadv14_dat_snoop_incoming_arp_request(struct batadv14_priv *bat_priv,
				      struct sk_buff *skb, int hdr_size)
{
	return false;
}

static inline bool
batadv14_dat_snoop_outgoing_arp_reply(struct batadv14_priv *bat_priv,
				    struct sk_buff *skb)
{
	return false;
}

static inline bool
batadv14_dat_snoop_incoming_arp_reply(struct batadv14_priv *bat_priv,
				    struct sk_buff *skb, int hdr_size)
{
	return false;
}

static inline bool
batadv14_dat_drop_broadcast_packet(struct batadv14_priv *bat_priv,
				 struct batadv14_forw_packet *forw_packet)
{
	return false;
}

static inline void
batadv14_dat_init_orig_node_addr(struct batadv14_orig_node *orig_node)
{
}

static inline void batadv14_dat_init_own_addr(struct batadv14_priv *bat_priv,
					    struct batadv14_hard_iface *iface)
{
}

static inline void batadv14_arp_change_timeout(struct net_device *soft_iface,
					     const char *name)
{
}

static inline int batadv14_dat_init(struct batadv14_priv *bat_priv)
{
	return 0;
}

static inline void batadv14_dat_free(struct batadv14_priv *bat_priv)
{
}

static inline void batadv14_dat_inc_counter(struct batadv14_priv *bat_priv,
					  uint8_t subtype)
{
}

#endif /* CONFIG_BATMAN_ADV14_DAT */

#endif /* _NET_BATMAN_ADV14_ARP_H_ */
