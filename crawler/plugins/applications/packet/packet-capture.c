#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include "/root/agentless-system-crawler-git/crawler/plugins/applications/packet/proto_num.h"

#define IP_TCP 	6   
#define ETH_HLEN 14

int packet_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;	
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}


	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	//retrieve ip src/dest and port src/dest of current packet
	//and save it into struct Key

	int i = 0;
	for ( i = 0; i < PROTO_NUM; i++){
		if ( (tcp->dst_port == proto_num[i]) || 
				(tcp->src_port == proto_num[i])){
			//bpf_trace_printk("dst port %d, src port %d\n", tcp->dst_port, tcp->src_port);
			goto PKT_MATCH;
		}
	}

	goto DROP;

	//keep the packet and send it to userspace retruning -1
	PKT_MATCH:

	//send packet to userspace returning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;

}
