/* Copyright (C) 2012-2013 B.A.T.M.A.N. contributors:
 *
 * Martin Hundebøll, Jeppe Ledet-Pedersen
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

#ifndef _NET_BATMAN_ADV14_NETWORK_CODING_H_
#define _NET_BATMAN_ADV14_NETWORK_CODING_H_

#ifdef CONFIG_BATMAN_ADV14_NC

int batadv14_nc_init(void);
int batadv14_nc_mesh_init(struct batadv14_priv *bat_priv);
void batadv14_nc_mesh_free(struct batadv14_priv *bat_priv);
void batadv14_nc_update_nc_node(struct batadv14_priv *bat_priv,
			      struct batadv14_orig_node *orig_node,
			      struct batadv14_orig_node *orig_neigh_node,
			      struct batadv14_ogm_packet *ogm_packet,
			      int is_single_hop_neigh);
void batadv14_nc_purge_orig(struct batadv14_priv *bat_priv,
			  struct batadv14_orig_node *orig_node,
			  bool (*to_purge)(struct batadv14_priv *,
					   struct batadv14_nc_node *));
void batadv14_nc_init_bat_priv(struct batadv14_priv *bat_priv);
void batadv14_nc_init_orig(struct batadv14_orig_node *orig_node);
bool batadv14_nc_skb_forward(struct sk_buff *skb,
			   struct batadv14_neigh_node *neigh_node);
void batadv14_nc_skb_store_for_decoding(struct batadv14_priv *bat_priv,
				      struct sk_buff *skb);
void batadv14_nc_skb_store_sniffed_unicast(struct batadv14_priv *bat_priv,
					 struct sk_buff *skb);
int batadv14_nc_nodes_seq_print_text(struct seq_file *seq, void *offset);
int batadv14_nc_init_debugfs(struct batadv14_priv *bat_priv);

#else /* ifdef CONFIG_BATMAN_ADV14_NC */

static inline int batadv14_nc_init(void)
{
	return 0;
}

static inline int batadv14_nc_mesh_init(struct batadv14_priv *bat_priv)
{
	return 0;
}

static inline void batadv14_nc_mesh_free(struct batadv14_priv *bat_priv)
{
	return;
}

static inline void
batadv14_nc_update_nc_node(struct batadv14_priv *bat_priv,
			 struct batadv14_orig_node *orig_node,
			 struct batadv14_orig_node *orig_neigh_node,
			 struct batadv14_ogm_packet *ogm_packet,
			 int is_single_hop_neigh)
{
	return;
}

static inline void
batadv14_nc_purge_orig(struct batadv14_priv *bat_priv,
		     struct batadv14_orig_node *orig_node,
		     bool (*to_purge)(struct batadv14_priv *,
				      struct batadv14_nc_node *))
{
	return;
}

static inline void batadv14_nc_init_bat_priv(struct batadv14_priv *bat_priv)
{
	return;
}

static inline void batadv14_nc_init_orig(struct batadv14_orig_node *orig_node)
{
	return;
}

static inline bool batadv14_nc_skb_forward(struct sk_buff *skb,
					 struct batadv14_neigh_node *neigh_node)
{
	return false;
}

static inline void
batadv14_nc_skb_store_for_decoding(struct batadv14_priv *bat_priv,
				 struct sk_buff *skb)
{
	return;
}

static inline void
batadv14_nc_skb_store_sniffed_unicast(struct batadv14_priv *bat_priv,
				    struct sk_buff *skb)
{
	return;
}

static inline int batadv14_nc_nodes_seq_print_text(struct seq_file *seq,
						 void *offset)
{
	return 0;
}

static inline int batadv14_nc_init_debugfs(struct batadv14_priv *bat_priv)
{
	return 0;
}

#endif /* ifdef CONFIG_BATMAN_ADV14_NC */

#endif /* _NET_BATMAN_ADV14_NETWORK_CODING_H_ */
