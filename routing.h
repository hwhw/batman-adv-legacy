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

#ifndef _NET_BATMAN_ADV14_ROUTING_H_
#define _NET_BATMAN_ADV14_ROUTING_H_

bool batadv14_check_management_packet(struct sk_buff *skb,
				    struct batadv14_hard_iface *hard_iface,
				    int header_len);
void batadv14_update_route(struct batadv14_priv *bat_priv,
			 struct batadv14_orig_node *orig_node,
			 struct batadv14_neigh_node *neigh_node);
int batadv14_recv_icmp_packet(struct sk_buff *skb,
			    struct batadv14_hard_iface *recv_if);
int batadv14_recv_unicast_packet(struct sk_buff *skb,
			       struct batadv14_hard_iface *recv_if);
int batadv14_recv_ucast_frag_packet(struct sk_buff *skb,
				  struct batadv14_hard_iface *recv_if);
int batadv14_recv_bcast_packet(struct sk_buff *skb,
			     struct batadv14_hard_iface *recv_if);
int batadv14_recv_vis_packet(struct sk_buff *skb,
			   struct batadv14_hard_iface *recv_if);
int batadv14_recv_tt_query(struct sk_buff *skb,
			 struct batadv14_hard_iface *recv_if);
int batadv14_recv_roam_adv(struct sk_buff *skb,
			 struct batadv14_hard_iface *recv_if);
struct batadv14_neigh_node *
batadv14_find_router(struct batadv14_priv *bat_priv,
		   struct batadv14_orig_node *orig_node,
		   const struct batadv14_hard_iface *recv_if);
void batadv14_bonding_candidate_del(struct batadv14_orig_node *orig_node,
				  struct batadv14_neigh_node *neigh_node);
void batadv14_bonding_candidate_add(struct batadv14_orig_node *orig_node,
				  struct batadv14_neigh_node *neigh_node);
void batadv14_bonding_save_primary(const struct batadv14_orig_node *orig_node,
				 struct batadv14_orig_node *orig_neigh_node,
				 const struct batadv14_ogm_packet
				 *batman_ogm_packet);
int batadv14_window_protected(struct batadv14_priv *bat_priv, int32_t seq_num_diff,
			    unsigned long *last_reset);

#endif /* _NET_BATMAN_ADV14_ROUTING_H_ */
