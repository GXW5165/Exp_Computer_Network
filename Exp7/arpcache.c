#include "arpcache.h"
void *arpcache_sweep(void *arg);
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <time.h>
static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	int found = 0;

	pthread_mutex_lock(&arpcache.lock);
	for (int i = 0; i < MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);

	return found;
}

void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);

	int idx = -1;
	for (int i = 0; i < MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
			idx = i;
			break;
		}
		if (idx == -1 && !arpcache.entries[i].valid)
			idx = i;
	}
	if (idx == -1)
		idx = rand() % MAX_ARP_SIZE;

	arpcache.entries[idx].ip4 = ip4;
	memcpy(arpcache.entries[idx].mac, mac, ETH_ALEN);
	arpcache.entries[idx].added = time(NULL);
	arpcache.entries[idx].valid = 1;

	if (!list_empty(&arpcache.req_list)) {
		struct arp_req *req = NULL, *q = NULL;
		list_for_each_entry_safe(req, q, &arpcache.req_list, list) {
			if (req->ip4 == ip4) {
				struct cached_pkt *pkt = NULL, *pkt_q = NULL;
				list_for_each_entry_safe(pkt, pkt_q, &req->cached_packets, list) {
					struct ether_header *eh = (struct ether_header *)pkt->packet;
					memcpy(eh->ether_dhost, mac, ETH_ALEN);
					memcpy(eh->ether_shost, req->iface->mac, ETH_ALEN);
					eh->ether_type = htons(ETH_P_IP);

					list_delete_entry(&pkt->list);
					iface_send_packet(req->iface, pkt->packet, pkt->len);
					free(pkt);
				}

				list_delete_entry(&req->list);
				free(req);
				break;
			}
		}
	}

	pthread_mutex_unlock(&arpcache.lock);
}

void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	int need_request = 0;

	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req = NULL;
	if (!list_empty(&arpcache.req_list)) {
		struct arp_req *iter = NULL;
		list_for_each_entry(iter, &arpcache.req_list, list) {
			if (iter->iface == iface && iter->ip4 == ip4) {
				req = iter;
				break;
			}
		}
	}

	if (!req) {
		req = malloc(sizeof(struct arp_req));
		bzero(req, sizeof(struct arp_req));
		init_list_head(&req->list);
		init_list_head(&req->cached_packets);
		req->iface = iface;
		req->ip4 = ip4;
		req->sent = time(NULL);
		req->retries = 1;
		list_add_tail(&req->list, &arpcache.req_list);
		need_request = 1;
	}

	struct cached_pkt *pkt = malloc(sizeof(struct cached_pkt));
	bzero(pkt, sizeof(struct cached_pkt));
	init_list_head(&pkt->list);
	pkt->packet = packet;
	pkt->len = len;
	list_add_tail(&pkt->list, &req->cached_packets);

	pthread_mutex_unlock(&arpcache.lock);

	if (need_request)
		arp_send_request(iface, ip4);
}

void *arpcache_sweep(void *arg)
{
	while (1) {
		sleep(1);

		time_t now = time(NULL);
		struct list_head failed_list;
		init_list_head(&failed_list);

		pthread_mutex_lock(&arpcache.lock);

		for (int i = 0; i < MAX_ARP_SIZE; i++) {
			if (arpcache.entries[i].valid && now - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)
				arpcache.entries[i].valid = 0;
		}

		if (!list_empty(&arpcache.req_list)) {
			struct arp_req *req = NULL, *q = NULL;
			list_for_each_entry_safe(req, q, &arpcache.req_list, list) {
				if (now - req->sent >= 1) {
					if (req->retries >= ARP_REQUEST_MAX_RETRIES) {
						list_delete_entry(&req->list);
						list_add_tail(&req->list, &failed_list);
					} else {
						req->sent = now;
						req->retries++;
						arp_send_request(req->iface, req->ip4);
					}
				}
			}
		}

		pthread_mutex_unlock(&arpcache.lock);

		if (!list_empty(&failed_list)) {
			struct arp_req *req = NULL, *q = NULL;
			list_for_each_entry_safe(req, q, &failed_list, list) {
				struct cached_pkt *pkt = NULL, *pkt_q = NULL;
				list_for_each_entry_safe(pkt, pkt_q, &req->cached_packets, list) {
					list_delete_entry(&pkt->list);
					icmp_send_packet(pkt->packet, pkt->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
					free(pkt->packet);
					free(pkt);
				}

				list_delete_entry(&req->list);
				free(req);
			}
		}
	}

	return NULL;
}