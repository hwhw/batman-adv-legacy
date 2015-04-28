/* Copyright (C) 2009-2013 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner
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

#ifndef _NET_BATMAN_ADV14_GATEWAY_CLIENT_H_
#define _NET_BATMAN_ADV14_GATEWAY_CLIENT_H_

void batadv14_gw_deselect(struct batadv14_priv *bat_priv);
void batadv14_gw_election(struct batadv14_priv *bat_priv);
struct batadv14_orig_node *
batadv14_gw_get_selected_orig(struct batadv14_priv *bat_priv);
void batadv14_gw_check_election(struct batadv14_priv *bat_priv,
			      struct batadv14_orig_node *orig_node);
void batadv14_gw_node_update(struct batadv14_priv *bat_priv,
			   struct batadv14_orig_node *orig_node,
			   uint8_t new_gwflags);
void batadv14_gw_node_delete(struct batadv14_priv *bat_priv,
			   struct batadv14_orig_node *orig_node);
void batadv14_gw_node_purge(struct batadv14_priv *bat_priv);
int batadv14_gw_client_seq_print_text(struct seq_file *seq, void *offset);
bool batadv14_gw_is_dhcp_target(struct sk_buff *skb, unsigned int *header_len);
bool batadv14_gw_out_of_range(struct batadv14_priv *bat_priv, struct sk_buff *skb);

#endif /* _NET_BATMAN_ADV14_GATEWAY_CLIENT_H_ */
