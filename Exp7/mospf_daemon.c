#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "ether.h"
#include "rtable.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

#define INF 0x3fffffff
#define MAX_NODE 256
#define MAX_ROUTE 1024

static const u8 mospf_mcast_mac[ETH_ALEN] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x05};

typedef struct {
	u32 dest;
	u32 mask;
	u32 owner;
	int dist;
} route_candidate_t;

static int is_direct_network(u32 network, u32 mask)
{
	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if ((iface->ip & mask) == network && iface->mask == mask)
			return 1;
	}
	return 0;
}

static int find_router(u32 *routers, int n, u32 rid)
{
	for (int i = 0; i < n; ++i) {
		if (routers[i] == rid)
			return i;
	}
	return -1;
}

static int add_router(u32 *routers, int *n, u32 rid)
{
	int idx = find_router(routers, *n, rid);
	if (idx >= 0)
		return idx;
	if (*n >= MAX_NODE)
		return -1;
	routers[*n] = rid;
	return (*n)++;
}

static int find_first_hop(int src, int dst, int *prev)
{
	int cur = dst;
	if (src == dst)
		return -1;
	while (prev[cur] != -1 && prev[cur] != src)
		cur = prev[cur];
	if (prev[cur] == src)
		return cur;
	return -1;
}

static int find_nbr_by_rid(u32 rid, iface_info_t **out_iface, u32 *out_ip)
{
	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list) {
		mospf_nbr_t *nbr;
		list_for_each_entry(nbr, &iface->nbr_list, list) {
			if (nbr->nbr_id == rid) {
				if (out_iface)
					*out_iface = iface;
				if (out_ip)
					*out_ip = nbr->nbr_ip;
				return 1;
			}
		}
	}
	return 0;
}

static void add_route_candidate(route_candidate_t *cands, int *cnt,
		u32 dest, u32 mask, u32 owner, int dist)
{
	if (dest == 0 || mask == 0 || is_direct_network(dest, mask))
		return;

	for (int i = 0; i < *cnt; ++i) {
		if (cands[i].dest == dest && cands[i].mask == mask) {
			if (dist < cands[i].dist) {
				cands[i].owner = owner;
				cands[i].dist = dist;
			}
			return;
		}
	}

	if (*cnt < MAX_ROUTE) {
		cands[*cnt].dest = dest;
		cands[*cnt].mask = mask;
		cands[*cnt].owner = owner;
		cands[*cnt].dist = dist;
		(*cnt)++;
	}
}

static void update_mospf_rtable()
{
	u32 routers[MAX_NODE];
	int graph[MAX_NODE][MAX_NODE];
	int dist[MAX_NODE], prev[MAX_NODE], visited[MAX_NODE];
	int nrouters = 0;

	for (int i = 0; i < MAX_NODE; ++i) {
		for (int j = 0; j < MAX_NODE; ++j)
			graph[i][j] = INF;
		graph[i][i] = 0;
	}

	int self = add_router(routers, &nrouters, instance->router_id);

	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list) {
		mospf_nbr_t *nbr;
		list_for_each_entry(nbr, &iface->nbr_list, list) {
			int v = add_router(routers, &nrouters, nbr->nbr_id);
			if (v >= 0) {
				graph[self][v] = 1;
				graph[v][self] = 1;
			}
		}
	}

	mospf_db_entry_t *entry;
	list_for_each_entry(entry, &mospf_db, list) {
		int u = add_router(routers, &nrouters, entry->rid);
		if (u < 0 || entry->array == NULL)
			continue;

		for (int i = 0; i < entry->nadv; ++i) {
			if (entry->array[i].rid == 0)
				continue;

			int v = add_router(routers, &nrouters, entry->array[i].rid);
			if (v >= 0) {
				if (entry->array[i].rid == instance->router_id &&
						!find_nbr_by_rid(entry->rid, NULL, NULL))
					continue;
				graph[u][v] = 1;
				graph[v][u] = 1;
			}
		}
	}

	for (int i = 0; i < nrouters; ++i) {
		dist[i] = INF;
		prev[i] = -1;
		visited[i] = 0;
	}
	dist[self] = 0;

	for (int i = 0; i < nrouters; ++i) {
		int u = -1;
		for (int j = 0; j < nrouters; ++j) {
			if (!visited[j] && (u == -1 || dist[j] < dist[u]))
				u = j;
		}
		if (u == -1 || dist[u] == INF)
			break;

		visited[u] = 1;
		for (int v = 0; v < nrouters; ++v) {
			if (!visited[v] && graph[u][v] < INF && dist[u] + graph[u][v] < dist[v]) {
				dist[v] = dist[u] + graph[u][v];
				prev[v] = u;
			}
		}
	}

	clear_rtable();
	load_rtable_from_kernel();

	route_candidate_t cands[MAX_ROUTE];
	int ncands = 0;

	list_for_each_entry(entry, &mospf_db, list) {
		int owner = find_router(routers, nrouters, entry->rid);
		if (owner < 0 || dist[owner] == INF || entry->array == NULL)
			continue;

		for (int i = 0; i < entry->nadv; ++i) {
			u32 dest = entry->array[i].network;
			u32 mask = entry->array[i].mask;
			add_route_candidate(cands, &ncands, dest, mask, entry->rid, dist[owner]);
		}
	}

	for (int i = 0; i < ncands; ++i) {
		int owner = find_router(routers, nrouters, cands[i].owner);
		if (owner < 0 || owner == self || dist[owner] == INF)
			continue;

		int first_hop = find_first_hop(self, owner, prev);
		if (first_hop < 0)
			continue;

		iface_info_t *out_iface = NULL;
		u32 gw = 0;
		if (find_nbr_by_rid(routers[first_hop], &out_iface, &gw)) {
			rt_entry_t *rt = new_rt_entry(cands[i].dest, cands[i].mask, gw, out_iface);
			add_rt_entry(rt);
		}
	}
}

static int get_lsa_number()
{
	int nadv = 0;
	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list) {
		nadv += iface->num_nbr > 0 ? iface->num_nbr : 1;
	}
	return nadv;
}

static void fill_lsa_array(struct mospf_lsa *array)
{
	int idx = 0;
	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list) {
		u32 network = iface->ip & iface->mask;

		if (iface->num_nbr == 0) {
			array[idx].network = htonl(network);
			array[idx].mask = htonl(iface->mask);
			array[idx].rid = htonl(0);
			idx++;
		}
		else {
			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				array[idx].network = htonl(network);
				array[idx].mask = htonl(iface->mask);
				array[idx].rid = htonl(nbr->nbr_id);
				idx++;
			}
		}
	}
}

static void send_mospf_hello(iface_info_t *iface)
{
	int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
	char *packet = malloc(len);
	if (!packet)
		return;

	memset(packet, 0, len);

	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_dhost, mospf_mcast_mac, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	struct iphdr *ip = packet_to_ip_hdr(packet);
	ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters,
			IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE,
			IPPROTO_MOSPF);

	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	mospf_init_hdr(mospf, MOSPF_TYPE_HELLO,
			MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE,
			instance->router_id, instance->area_id);

	struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
	mospf_init_hello(hello, iface->mask);
	mospf->checksum = mospf_checksum(mospf);

	iface_send_packet(iface, packet, len);
}

static void send_mospf_lsu(iface_info_t *excluded_iface)
{
	int nadv = get_lsa_number();
	int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * MOSPF_LSA_SIZE;

	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (excluded_iface && iface == excluded_iface)
			continue;

		char *packet = malloc(len);
		if (!packet)
			continue;

		memset(packet, 0, len);

		struct ether_header *eh = (struct ether_header *)packet;
		memcpy(eh->ether_dhost, mospf_mcast_mac, ETH_ALEN);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		eh->ether_type = htons(ETH_P_IP);

		struct iphdr *ip = packet_to_ip_hdr(packet);
		ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters,
				IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * MOSPF_LSA_SIZE,
				IPPROTO_MOSPF);

		struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
		mospf_init_hdr(mospf, MOSPF_TYPE_LSU,
				MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * MOSPF_LSA_SIZE,
				instance->router_id, instance->area_id);

		struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
		mospf_init_lsu(lsu, nadv);

		struct mospf_lsa *array = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
		fill_lsa_array(array);

		mospf->checksum = mospf_checksum(mospf);
		iface_send_packet(iface, packet, len);
	}
}

static void forward_mospf_lsu(iface_info_t *in_iface, const char *packet, int len)
{
	struct iphdr *old_ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *old_mospf = (struct mospf_hdr *)((char *)old_ip + IP_HDR_SIZE(old_ip));
	struct mospf_lsu *old_lsu = (struct mospf_lsu *)((char *)old_mospf + MOSPF_HDR_SIZE);

	if (old_lsu->ttl <= 1)
		return;

	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface == in_iface)
			continue;

		char *new_packet = malloc(len);
		if (!new_packet)
			continue;

		memcpy(new_packet, packet, len);

		struct ether_header *eh = (struct ether_header *)new_packet;
		memcpy(eh->ether_dhost, mospf_mcast_mac, ETH_ALEN);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		eh->ether_type = htons(ETH_P_IP);

		struct iphdr *ip = packet_to_ip_hdr(new_packet);
		ip->saddr = htonl(iface->ip);
		ip->daddr = htonl(MOSPF_ALLSPFRouters);
		ip->checksum = ip_checksum(ip);

		struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
		struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
		lsu->ttl--;
		mospf->checksum = mospf_checksum(mospf);

		iface_send_packet(iface, new_packet, len);
	}
}

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		iface->num_nbr = 0;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	while (1) {
		pthread_mutex_lock(&mospf_lock);

		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list) {
			send_mospf_hello(iface);
		}

		pthread_mutex_unlock(&mospf_lock);
		sleep(MOSPF_DEFAULT_HELLOINT);
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	while (1) {
		sleep(1);
		int changed = 0;

		pthread_mutex_lock(&mospf_lock);

		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list) {
			mospf_nbr_t *nbr, *q;
			list_for_each_entry_safe(nbr, q, &iface->nbr_list, list) {
				nbr->alive++;
				if (nbr->alive > MOSPF_HELLO_TIMEOUT) {
					list_delete_entry(&nbr->list);
					free(nbr);
					iface->num_nbr--;
					changed = 1;
				}
			}
		}

		if (changed) {
			instance->sequence_num++;
			send_mospf_lsu(NULL);
			update_mospf_rtable();
		}

		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_database_thread(void *param)
{
	while (1) {
		sleep(1);
		int changed = 0;

		pthread_mutex_lock(&mospf_lock);

		mospf_db_entry_t *entry, *q;
		list_for_each_entry_safe(entry, q, &mospf_db, list) {
			entry->alive++;
			if (entry->alive > MOSPF_DATABASE_TIMEOUT) {
				list_delete_entry(&entry->list);
				free(entry->array);
				free(entry);
				changed = 1;
			}
		}

		if (changed)
			update_mospf_rtable();

		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);

	u32 rid = ntohl(mospf->rid);
	if (rid == instance->router_id)
		return;

	u32 nbr_ip = ntohl(ip->saddr);
	u32 nbr_mask = ntohl(hello->mask);
	int changed = 0;

	pthread_mutex_lock(&mospf_lock);

	mospf_nbr_t *nbr;
	list_for_each_entry(nbr, &iface->nbr_list, list) {
		if (nbr->nbr_id == rid) {
			nbr->nbr_ip = nbr_ip;
			nbr->nbr_mask = nbr_mask;
			nbr->alive = 0;
			pthread_mutex_unlock(&mospf_lock);
			return;
		}
	}

	nbr = malloc(sizeof(mospf_nbr_t));
	if (nbr) {
		nbr->nbr_id = rid;
		nbr->nbr_ip = nbr_ip;
		nbr->nbr_mask = nbr_mask;
		nbr->alive = 0;
		list_add_tail(&nbr->list, &iface->nbr_list);
		iface->num_nbr++;
		changed = 1;
	}

	if (changed) {
		instance->sequence_num++;
		send_mospf_lsu(NULL);
		update_mospf_rtable();
	}

	pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	while (1) {
		sleep(instance->lsuint);

		pthread_mutex_lock(&mospf_lock);
		instance->sequence_num++;
		send_mospf_lsu(NULL);
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	struct mospf_lsa *lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);

	u32 rid = ntohl(mospf->rid);
	if (rid == instance->router_id)
		return;

	u16 seq = ntohs(lsu->seq);
	int nadv = ntohl(lsu->nadv);
	int changed = 0;

	pthread_mutex_lock(&mospf_lock);

	mospf_db_entry_t *entry;
	list_for_each_entry(entry, &mospf_db, list) {
		if (entry->rid == rid) {
			if (entry->seq < seq) {
				struct mospf_lsa *new_array = malloc(nadv * sizeof(struct mospf_lsa));
				if (!new_array) {
					pthread_mutex_unlock(&mospf_lock);
					return;
				}
				for (int i = 0; i < nadv; ++i) {
					new_array[i].network = ntohl(lsa[i].network);
					new_array[i].mask = ntohl(lsa[i].mask);
					new_array[i].rid = ntohl(lsa[i].rid);
				}
				free(entry->array);
				entry->array = new_array;
				entry->seq = seq;
				entry->nadv = nadv;
				entry->alive = 0;
				changed = 1;
			}
			else {
				entry->alive = 0;
			}

			if (changed) {
				forward_mospf_lsu(iface, packet, len);
				update_mospf_rtable();
			}

			pthread_mutex_unlock(&mospf_lock);
			return;
		}
	}

	entry = malloc(sizeof(mospf_db_entry_t));
	if (entry) {
		entry->array = malloc(nadv * sizeof(struct mospf_lsa));
		if (!entry->array) {
			free(entry);
			pthread_mutex_unlock(&mospf_lock);
			return;
		}

		entry->rid = rid;
		entry->seq = seq;
		entry->nadv = nadv;
		entry->alive = 0;

		for (int i = 0; i < nadv; ++i) {
			entry->array[i].network = ntohl(lsa[i].network);
			entry->array[i].mask = ntohl(lsa[i].mask);
			entry->array[i].rid = ntohl(lsa[i].rid);
		}

		list_add_tail(&entry->list, &mospf_db);
		changed = 1;
	}

	if (changed) {
		forward_mospf_lsu(iface, packet, len);
		update_mospf_rtable();
	}

	pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
