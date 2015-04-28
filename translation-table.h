/* Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich, Antonio Quartulli
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

#ifndef _NET_BATMAN_ADV14_TRANSLATION_TABLE_H_
#define _NET_BATMAN_ADV14_TRANSLATION_TABLE_H_

int batadv14_tt_len(int changes_num);
int batadv14_tt_init(struct batadv14_priv *bat_priv);
void batadv14_tt_local_add(struct net_device *soft_iface, const uint8_t *addr,
			 int ifindex);
uint16_t batadv14_tt_local_remove(struct batadv14_priv *bat_priv,
				const uint8_t *addr, const char *message,
				bool roaming);
int batadv14_tt_local_seq_print_text(struct seq_file *seq, void *offset);
void batadv14_tt_global_add_orig(struct batadv14_priv *bat_priv,
			       struct batadv14_orig_node *orig_node,
			       const unsigned char *tt_buff, int tt_buff_len);
int batadv14_tt_global_add(struct batadv14_priv *bat_priv,
			 struct batadv14_orig_node *orig_node,
			 const unsigned char *addr, uint16_t flags,
			 uint8_t ttvn);
int batadv14_tt_global_seq_print_text(struct seq_file *seq, void *offset);
void batadv14_tt_global_del_orig(struct batadv14_priv *bat_priv,
			       struct batadv14_orig_node *orig_node,
			       const char *message);
struct batadv14_orig_node *batadv14_transtable_search(struct batadv14_priv *bat_priv,
						  const uint8_t *src,
						  const uint8_t *addr);
void batadv14_tt_free(struct batadv14_priv *bat_priv);
bool batadv14_send_tt_response(struct batadv14_priv *bat_priv,
			     struct batadv14_tt_query_packet *tt_request);
bool batadv14_is_my_client(struct batadv14_priv *bat_priv, const uint8_t *addr);
void batadv14_handle_tt_response(struct batadv14_priv *bat_priv,
			       struct batadv14_tt_query_packet *tt_response);
bool batadv14_is_ap_isolated(struct batadv14_priv *bat_priv, uint8_t *src,
			   uint8_t *dst);
void batadv14_tt_update_orig(struct batadv14_priv *bat_priv,
			   struct batadv14_orig_node *orig_node,
			   const unsigned char *tt_buff, uint8_t tt_num_changes,
			   uint8_t ttvn, uint16_t tt_crc);
int batadv14_tt_append_diff(struct batadv14_priv *bat_priv,
			  unsigned char **packet_buff, int *packet_buff_len,
			  int packet_min_len);
bool batadv14_tt_global_client_is_roaming(struct batadv14_priv *bat_priv,
					uint8_t *addr);
bool batadv14_tt_local_client_is_roaming(struct batadv14_priv *bat_priv,
				       uint8_t *addr);
bool batadv14_tt_add_temporary_global_entry(struct batadv14_priv *bat_priv,
					  struct batadv14_orig_node *orig_node,
					  const unsigned char *addr);

#endif /* _NET_BATMAN_ADV14_TRANSLATION_TABLE_H_ */
