#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>

#define ONE_DAY_IN_SECS 86400

// #define FORWARD

uint8_t pool[4][256];

enum OP_CODES {
	OP_BOOTREQUEST = 1,
	OP_BOOTREPLY
};

// DHCP packet according to RFC 2131`
struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint64_t xid;
	uint32_t secs;
	uint32_t flags;
	uint64_t ciaddr;
	uint64_t yiaddr;
	uint64_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	// Technically this is of variable length but whatever
	uint8_t var[256];
};

void dhcp_discover_handler(struct dhcp_packet *packet, void (*reply)(struct dhcp_packet *)) {
	#ifdef FORWARD
		// code here to forward request to the bethel dhcp server
		// Sort of like a bootp relay
	#else
	// TODO: IP addr allocation and managment
	
	struct dhcp_packet *reply_packet = malloc(sizeof(struct dhcp_packet));
	memset(reply_packet, 0, sizeof(struct dhcp_packet));

	reply_packet->op = OP_BOOTREPLY;

	if (reply_packet == NULL) {
		// IDK what to do here
		return;
	}

	if (packet->ciaddr != 0) {
		reply_packet->ciaddr = packet->ciaddr;
	} else {
		// TODO: Assign IP Here
	}



	#endif


}

void packet_listener() {
	int sock, i;
	uint8_t buffer[256];
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sock == -1) {
		switch (errno) {
			case 1: printf("This program needs to be run as root\n"); break;
			default: printf("ERROR 76 %d\n", errno); break;
		}
		
		return;
	}

	struct ifreq ifinfo;
	memset(&ifinfo, 0, sizeof(struct ifreq));
	// snprintf(ifinfo.ifr_name, sizeof(ifinfo.ifr_name), "wlan0");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifinfo, sizeof(ifinfo)) == -1) {
		printf("ERROR Binding: %d\n", errno);
		return;
	}

	while (1) {
		if (recv(sock, buffer, sizeof(buffer), 0) > 0) {
			for (i = 0; i < sizeof(buffer); i++) {
				printf("%d: 0x%x\n", i, buffer[i]);	
			}
		}
	}
	
}

void pcap_packet_listener() {
	char errbuf[PCAP_ERRBUF_SIZE];
	int result;
	uint32_t pktcnt = 0;
	struct pcap_pkthdr *pkthdr;
	uint8_t *pktdata;
	pcap_t *pcap_instance = NULL;

	if (pcap_init(0, errbuf)) {
		printf("Error initialising PCAP, error message: %s\n", errbuf);
		return;
	}

	// pcap_t *pcap_instance = pcap_create("eth0", errbuf);
	pcap_instance = pcap_open_live(NULL, 262144, 1, 2000, errbuf);

	if (pcap_instance == NULL) {
		printf("Error creating PCAP instance, error message: %s\n", errbuf);
		return;
	}

// 	result = pcap_activate(pcap_instance);
//
//	switch (result) {
//		case 0: break;
//		case PCAP_WARNING_PROMISC_NOTSUP: {
//			printf("This device doesn't support promiscuous mode\n");
//			pcap_close(pcap_instance);
//			pcap_instance = NULL;
//			return;
//		}
//		default: {
//			printf("Error activating pcap_instance, error code: %d\n%s\n", result, pcap_statustostr(result));
//			pcap_close(pcap_instance);
//			pcap_instance = NULL;
//			return;
//		}
//	}

	printf("Working\n");

	while (1) {
		if (!pcap_next_ex(pcap_instance, &pkthdr, &pktdata)) {
			printf("Error Reading packet\n");
			pcap_close(pcap_instance);
			pcap_instance = NULL;
			return;
		}

		fprintf(stderr, "Packet %d, len: %d\n", pktcnt, pkthdr->len);
		pktcnt++;
	}
}

int main(void) {
	// packet_listener();
	pcap_packet_listener();
	return 0;
}
