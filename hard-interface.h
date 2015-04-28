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

#ifndef _NET_BATMAN_ADV14_HARD_INTERFACE_H_
#define _NET_BATMAN_ADV14_HARD_INTERFACE_H_

enum batadv14_hard_if_state {
	BATADV_IF_NOT_IN_USE,
	BATADV_IF_TO_BE_REMOVED,
	BATADV_IF_INACTIVE,
	BATADV_IF_ACTIVE,
	BATADV_IF_TO_BE_ACTIVATED,
	BATADV_IF_I_WANT_YOU,
};

/**
 * enum batadv14_hard_if_cleanup - Cleanup modi for soft_iface after slave removal
 * @BATADV_IF_CLEANUP_KEEP: Don't automatically delete soft-interface
 * @BATADV_IF_CLEANUP_AUTO: Delete soft-interface after last slave was removed
 */
enum batadv14_hard_if_cleanup {
	BATADV_IF_CLEANUP_KEEP,
	BATADV_IF_CLEANUP_AUTO,
};

extern struct notifier_block batadv14_hard_if_notifier;

struct batadv14_hard_iface*
batadv14_hardif_get_by_netdev(const struct net_device *net_dev);
int batadv14_hardif_enable_interface(struct batadv14_hard_iface *hard_iface,
				   const char *iface_name);
void batadv14_hardif_disable_interface(struct batadv14_hard_iface *hard_iface,
				     enum batadv14_hard_if_cleanup autodel);
void batadv14_hardif_remove_interfaces(void);
int batadv14_hardif_min_mtu(struct net_device *soft_iface);
void batadv14_update_min_mtu(struct net_device *soft_iface);
void batadv14_hardif_free_rcu(struct rcu_head *rcu);
bool batadv14_is_wifi_iface(int ifindex);

static inline void
batadv14_hardif_free_ref(struct batadv14_hard_iface *hard_iface)
{
	if (atomic_dec_and_test(&hard_iface->refcount))
		call_rcu(&hard_iface->rcu, batadv14_hardif_free_rcu);
}

static inline struct batadv14_hard_iface *
batadv14_primary_if_get_selected(struct batadv14_priv *bat_priv)
{
	struct batadv14_hard_iface *hard_iface;

	rcu_read_lock();
	hard_iface = rcu_dereference(bat_priv->primary_if);
	if (!hard_iface)
		goto out;

	if (!atomic_inc_not_zero(&hard_iface->refcount))
		hard_iface = NULL;

out:
	rcu_read_unlock();
	return hard_iface;
}

#endif /* _NET_BATMAN_ADV14_HARD_INTERFACE_H_ */
