#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>


struct route_table_entry *get_best_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len) {

	for(int i = 0; i < rtable_len; i++)
		if((ip_dest & rtable[i].mask) == rtable[i].prefix)
			return (rtable + i);

	return NULL;
}

struct arp_table_entry *get_arp_entry(uint32_t ip, struct arp_table_entry *arp_table, int arp_table_len) {

	for(int i = 0; i < arp_table_len; i++)
		if(arp_table[i].ip == ip)
			return (arp_table + i);

	return NULL;		
}

int compare_rtable_entries(const void *a, const void *b) {

    const struct route_table_entry *entry1 = (const struct route_table_entry *)a;
    const struct route_table_entry *entry2 = (const struct route_table_entry *)b;

    // prefix comparison
    if (ntohl(entry1->prefix) != ntohl(entry2->prefix))
        return (ntohl(entry1->prefix) > ntohl(entry2->prefix)) ? -1 : 1;
    
	// mask comparison
    return (ntohl(entry1->mask) > ntohl(entry2->mask)) ? -1 : 1;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(70000 * sizeof(struct route_table_entry));
	struct arp_table_entry *arp_table = malloc(60 * sizeof(struct arp_table_entry)); 

	int rtable_len = read_rtable(argv[1], rtable);
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_rtable_entries);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));

		// Bad checksum, ignore
		if(checksum((uint16_t *) ip_header, sizeof(struct iphdr)) != 0)
			continue;

		struct route_table_entry *best_route = get_best_route(ip_header->daddr, rtable, rtable_len);
		
		// Bad ttl, ignore
		if(ip_header->ttl < 1)
			continue;

		int old_ttl = ip_header->ttl;
		int old_check = ip_header->check;
		ip_header->ttl--;

		ip_header->check = ~(~old_check + ~((uint16_t) old_ttl) + ((uint16_t)ip_header->ttl)) - 1;

		struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop, arp_table, arp_table_len);

		if(arp_entry == NULL)
			continue;

		// memcpy
		for(int i = 0; i < 6; i++)
			eth_hdr->ether_dhost[i] = arp_entry->mac[i];

		uint8_t mac[6];
		get_interface_mac(best_route->interface, mac);

		for(int i = 0; i < 6; i++)
			eth_hdr->ether_shost[i] = mac[i];

		send_to_link(best_route->interface, buf, len);				

	}
}

