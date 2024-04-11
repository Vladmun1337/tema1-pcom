#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define IP_ETHTYPE 0x0800
#define ARP_ETHTYPE 0x0806
#define OP_REQUEST 1
#define OP_REPLY 2
#define HTYPE_ETHER 1
#define TIMEOUT 11
#define NO_HOST 3

struct route_table_entry *rtable;
struct arp_table_entry *arp_table;
int rtable_len;
int arp_table_len;
queue q;
int q_len;


/*
 * Search best next hop in routing table
 * Uses binary search comparing by prefix and mask
 * Routing table is in NETWORK ORDER
 * Params: ip - base ip that we will mask to find best prefix
 */
struct route_table_entry *get_best_route(uint32_t ip) {

	struct route_table_entry *my_entry = NULL;

	int left = 0;
	int right = rtable_len - 1;

	// keep in mind the rtable is sorted in decreasing order
	while(left <= right) {

		int mid = (left + right) / 2;

		// if current entry and newly found are equal, compare masks
		// except the case when current entry doesn't exist
		if((ip & rtable[mid].mask) == rtable[mid].prefix)
			if(!my_entry || ((my_entry != NULL) && (ntohl(my_entry->mask) < ntohl(rtable[mid].mask))))
				my_entry = &rtable[mid];

		if(ntohl(ip) >= ntohl(rtable[mid].prefix))
			right = mid - 1;
		else
			left = mid + 1;
	}

	return my_entry;

}

/*
 * Find MAC address in arp table
 * Uses basic linear search
 * Params: ip - ip address for the corresponding mac address in table
 */
struct arp_table_entry *get_arp_entry(uint32_t ip) {

	for(int i = 0; i < arp_table_len; i++)
		if(arp_table[i].ip == ip)
			return &arp_table[i];

	return NULL;	
}

/*
 * Comparator for qsort function used to sort routing tablr
 * Compares first the prefixes, in case of equality, compares masks
 * comparison made in HOST ORDER DECREASINGLY
 * PARAMS: a, b - entries in routing table to be compared cast as void pointers
 */
int rtable_comparator(const void *a, const void *b) {

    const struct route_table_entry *entry1 = (const struct route_table_entry *)a;
    const struct route_table_entry *entry2 = (const struct route_table_entry *)b;

    // prefix comparison
    if (ntohl(entry1->prefix) != ntohl(entry2->prefix))
        return (ntohl(entry1->prefix) > ntohl(entry2->prefix)) ? -1 : 1;
    
	// mask comparison
    return (ntohl(entry1->mask) > ntohl(entry2->mask)) ? -1 : 1;
}

/*
 * Handles arp request from specific host
 * Changes the destination and source of arp packet
 * Extracts MAC address of router and sends it back to host
 * Params: See 'send_ip_packet()' 
 */
void parse_arp_request(int interface, char *buf, int len) {

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

	// modify arp header to send back
	arp_hdr->op = htons(OP_REPLY);

	// source is new destination MAC
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	get_interface_mac(interface, arp_hdr->sha);

	// change destination IP to source and new source is address of interface
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = inet_addr(get_interface_ip(interface));

	// build ether header to send back reply
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	send_to_link(interface, buf, len);
}

/*
 * Extracts new MAC address from arp reply
 * Adds MAC with corresponding ip to the arp table
 * Searches for cached packets in queue that match newly added entry
 * Sends any cached packet it finds and frees up queue
 * Params: See 'send_ip_packet()' 
 */
void parse_arp_reply(int interface, char *buf, int len) {

	struct arp_header *arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

	// add new entry
	arp_table[arp_table_len].ip = arp_hdr->spa;
	memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);

	arp_table_len++;

	int new_len = q_len;

	// check cached ip packets
	while(q_len--) {
		struct packet_cache *packet = (struct packet_cache *) queue_deq(q);
		struct ether_header *packet_eth = (struct ether_header *) packet->buf;

		// check if cached packet matches newly found address
		if(ntohl(packet->next_hop) == ntohl(arp_hdr->spa)) {

			// build packet ether header to send
			get_interface_mac(packet->interface, packet_eth->ether_shost);
			memcpy(packet_eth->ether_dhost, arp_hdr->sha, 6);

			send_to_link(packet->interface, packet->buf, packet->len);

			// free memory and decrement total number of cached packets
			free(packet);
			//free(packet_eth);
			new_len--;
		} else {
			// put packet back into queue
			queue_enq(q, packet);
		}
	}

	q_len = new_len;
}

/*
 * Builds a new cached packet for a packet that can't be sent at the moment
 * Populates cache with packet's metadata (length, interface, next hop and data)
 * Adds cache to queue and increases queue size
 * Params:
 * best_route - routing data for next hop and next interface needed
 * buf - packet data
 * len - packet length
 */
void pack_and_queue(struct route_table_entry *best_route, char *buf, int len) {

	struct packet_cache *packet = malloc(sizeof(struct packet_cache));

	packet->len = len;
	packet->interface = best_route->interface;
	packet->next_hop = best_route->next_hop;
	packet->buf = malloc(len);
	memcpy(packet->buf, buf, len);

	queue_enq(q, packet);
	q_len++;
}

/*
 * Converts an ip packet to an ARP type by adding a specific header
 * Destination MAC of IP packet is unknown so the router sends a broadcast to network
 * Params:
 * buf - packet
 * route - rtable entry for best route
 * mac - destination MAC address (RECOMMENDED: 255:255:255:255:255:255)
 * len - packet length
 */
int populate_arp_header(char *buf, struct route_table_entry *route, uint8_t *mac, int len) {

	struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

	// set packet type
	arp_hdr->htype = htons(HTYPE_ETHER);
	arp_hdr->ptype = htons(IP_ETHTYPE);

	// MAC length and IP length
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;

	// set arp type (request here) and build source-destination fields
	arp_hdr->op = htons(OP_REQUEST);
	arp_hdr->spa = inet_addr(get_interface_ip(route->interface));
	get_interface_mac(route->interface, arp_hdr->sha);

	arp_hdr->tpa = route->next_hop;
	memcpy(arp_hdr->tha, mac, 6);

	// return new length (original + header overhead)
	return len + sizeof(struct arp_header);
}

/*
 * Sends an ICMP echo reply to source of echo request
 * Changes source-destination of packet and ICMP code + type
 * Params: buf - packet
*/
void echo_back(char *buf) {

	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_header = (struct icmphdr *)(ip_header + 1);

	// switch ip source and destination and recalculate checksum
	uint32_t aux_addr = ip_header->saddr;
	ip_header->saddr = ip_header->daddr;
	ip_header->daddr = aux_addr;

	ip_header->check = 0;
	ip_header->check = htons(checksum((uint16_t *) ip_header, sizeof(struct iphdr)));

	// switch icmp type and code for echo reply and recalculate checksum
	icmp_header->type = icmp_header->code = 0;

	icmp_header->checksum = 0;
	icmp_header->checksum = htons(checksum((uint16_t *) icmp_header, sizeof(struct icmphdr)));
}

/*
 * Converts an IP packet to ICMP
 * ICMP reply will depend on provided code
 * Saves first 64 bits of original IP request
 * Params:
 * interface - router's interface
 * buf - packet
 * len - packet length
 * type - ICMP response type
*/
int build_icmp_by_type(int interface, char *buf, int len, uint8_t type) {

	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_header = (struct icmphdr *)(ip_header + 1);

	// populate code + type and calculate icmp checksum
	icmp_header->code = 0;
	icmp_header->type = type;

	icmp_header->checksum = 0;
	icmp_header->checksum = htons(checksum((u_int16_t *) icmp_header, sizeof(struct icmphdr)));

	// copy first 64 bits of old ip data to end of icmp header
	memcpy((icmp_header + 1), ip_header, 8);

	// build new ip header
	ip_header->daddr = ip_header->saddr;
	ip_header->saddr = inet_addr(get_interface_ip(interface));

	// update TTL to standardized max
	ip_header->ttl = 64;

	// change protocol of packet from ip to icmp
	ip_header->protocol = IPPROTO_ICMP;

	// modify packet length to encapsulate icmp header and 64 bit stuffing
	// switch length to host order to properly add new length then switch back to network order
	ip_header->tot_len = htons(ntohs(ip_header->tot_len) + sizeof(struct icmphdr) + 64);

	ip_header->check = 0;
	ip_header->check = htons(checksum((u_int16_t *) ip_header, sizeof(struct iphdr)));

	return (len + sizeof(struct icmphdr) + 64);
}

/*
 * Redirects an IP packet
 * Checks checksum, TTL in case of packet drop
 * Searches next hop in routing table and MAC in arp table
 * 
 * NOTE:
 * rtable miss    -> host unreachable ICMP conversion
 * arp table miss -> sends ARP request to next hop IP for MAC address
 * 
 * Params:
 * interface - router's interface
 * buf - packet
 * len - packet length
 */
void send_ip_packet(int interface, char *buf, int len) {

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));

	// redirect icmp echo if router is destination
	if(ip_header->daddr == inet_addr(get_interface_ip(interface)))
		echo_back(buf);
	

	// Bad checksum, ignore
	if(checksum((uint16_t *) ip_header, sizeof(struct iphdr)) != 0)
		return;
		
	// Bad ttl, signal with icmp
	if(ip_header->ttl <= 1)
		len = build_icmp_by_type(interface, buf, len, TIMEOUT);

	struct route_table_entry *best_route = get_best_route(ip_header->daddr);

	if(!best_route) {
		len = build_icmp_by_type(interface, buf, len, NO_HOST);

		// find route back because previous route was empty
		best_route = get_best_route(ip_header->daddr);
	}	

	int old_ttl = ip_header->ttl;
	int old_check = ip_header->check;
	ip_header->ttl--;

	// new checksum
	ip_header->check = ~(~old_check + ~((uint16_t) old_ttl) + ((uint16_t)ip_header->ttl)) - 1;

	// find mac address in arp table
	struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);


	// chache IP in queue and build ARP request if no MAC address is available
	if(arp_entry == NULL) {

		// build packet cache with data and add to queue
		pack_and_queue(best_route, buf, len);

		// change ether header for arp request
		eth_hdr->ether_type = htons(ARP_ETHTYPE);
		get_interface_mac(interface, eth_hdr->ether_shost);

		// build broadcast address and set as destination
		uint8_t mac[6];
		for(int i = 0; i < 6; i++)
			mac[i] = 255;

		memcpy(eth_hdr->ether_dhost, mac, 6);

		// build arp header
		len = populate_arp_header(buf, best_route, mac, len);
		
	} else {

		// copy next hop's mac address to destination host
		memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

		uint8_t mac[6];
		get_interface_mac(best_route->interface, mac);

		// copy own mac address to source host
		memcpy(eth_hdr->ether_shost, mac, 6);
	}

	send_to_link(best_route->interface, buf, len);
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(70000 * sizeof(struct route_table_entry));
	arp_table = malloc(60 * sizeof(struct arp_table_entry)); 

	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), rtable_comparator);

	q = queue_create();
	q_len = 0;

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

		if(ntohs(eth_hdr->ether_type) == IP_ETHTYPE) {

			send_ip_packet(interface, buf, len);

		} else if(ntohs(eth_hdr->ether_type) == ARP_ETHTYPE) {

			if(ntohs(((struct arp_header*) (buf + sizeof(struct ether_header)))->op) == OP_REQUEST)

				parse_arp_request(interface, buf, len);

			else if(ntohs(((struct arp_header*) (buf + sizeof(struct ether_header)))->op) == OP_REPLY)

				parse_arp_reply(interface, buf, len);
		}
	}

	free(rtable);
	free(arp_table);
	free(q);
}

