#include "udp_server.h"
// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

#include <net/if.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/udp.h>  //Provides declarations for tcp header
#include <netinet/ip.h>	  //Provides declarations for ip header

#include "crc32.h"
#include "ib.h"

#include "ref_packets.h"

// ROCE Server port
#define SPORT 55410
#define PORT 4791
#define MAXLINE 1500

#define IP_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define HDR_SIZE IP_HDR_SIZE + UDP_HDR_SIZE

void initCrc(void);
uint32_t calc_icrc32(char *data, int len);

// BTH
uint32_t bth_psn = 0;
uint32_t crc = 0xFFFFFFFF;

int icmp, igmp, other, iphdrlen, ib, ib_conn_req;
struct sockaddr saddr;
struct sockaddr_in source, dest;

FILE *log_txt;

char data_out[MAXLINE];
char dest_mac[6];
char src_mac[6];

struct sockaddr saddr;
struct sockaddr_in source, dest;
struct ifreq ifreq_c, ifreq_i, ifreq_ip; /// for each ioctl keep diffrent ifreq structure otherwise error may come in sending(sendto )
#define INTF "eno2"
int total_len = 0, send_len;
unsigned char *sendbuff;
#define DESTMAC0 0xd0
#define DESTMAC1 0x67
#define DESTMAC2 0xe5
#define DESTMAC3 0x12
#define DESTMAC4 0x6f
#define DESTMAC5 0x8f

struct roce_input_msg
{
	struct ethhdr ethh;
	struct iphdr iph;
	struct udphdr udph;
	char payload[MAXLINE];
} __attribute__((packed));

void ib_send_rep(char *data_in, char *data_out)
{
	struct ib_base_transport_header *bth_in;
	struct ib_datagram_extended_transport_header *deth_in;
	struct ib_management_datagram_field *mad_in;
	struct ib_req *req;

	struct ib_base_transport_header *bth_out;
	struct ib_datagram_extended_transport_header *deth_out;
	struct ib_management_datagram_field *mad_out;
	struct ib_rep *rep;

	bth_in = (void *)&data_in[0];
	deth_in = (void *)&data_in[sizeof(struct ib_base_transport_header)];
	mad_in = (void *)&data_in[sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header)];
	req = (void *)&data_in[sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header) + sizeof(struct ib_management_datagram_field)];

	bth_out = (void *)&data_out[0];
	deth_out = (void *)&data_out[sizeof(struct ib_base_transport_header)];
	mad_out = (void *)&data_out[sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header)];
	rep = (void *)&data_out[sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header) + sizeof(struct ib_management_datagram_field)];

	memset(data_out, 0, 280);

	printf("ib_send_rep : opcode %x", bth_in->opcode);
	bth_out->opcode = bth_in->opcode;
	bth_out->se__m__padcnt__tver = bth_in->se__m__padcnt__tver;
	bth_out->pkey = bth_in->pkey;
	bth_out->dest_qp = bth_in->dest_qp;
	bth_out->ack__req = bth_in->ack__req;
	bth_out->ack__psn = ((bth_psn & 0xFF) << 16) + ((bth_psn & 0x00FF00)) + ((bth_psn & 0xFF0000) >> 16);
	bth_psn++;

	deth_out->qkey = deth_in->qkey;
	deth_out->src_qp = deth_in->src_qp;

	mad_out->ib_mad_params.method = mad_in->ib_mad_params.method;
	mad_out->ib_mad_params.r = mad_in->ib_mad_params.r;

	mad_out->class_version = mad_in->class_version;
	mad_out->mgmt_class = mad_in->mgmt_class;
	mad_out->base_version = mad_in->base_version;
	mad_out->class_specific = mad_in->class_specific;
	mad_out->status = mad_in->status;
	mad_out->transaction_id = mad_in->transaction_id;
	mad_out->attribute_id = htons(0x13);
	mad_out->attribute_modifier = mad_in->attribute_modifier;

	rep->local_comm_id = ntohl(0x1234);
	rep->remote_comm_id = req->local_comm_id;
	rep->local_q_key = ntohl(0x0);
	rep->local_qpn = req->ib_req_params_1.local_qpn;
	rep->local_eecn = ntohl(0x0);
	rep->starting_psn = 0xF; //ntohl(0xF);
	rep->resp_resources = 0x1;
	rep->initiator_depth = 0x1;
	rep->ib_rep_params_1.target_ack_delay = 0xF;
	rep->ib_rep_params_1.failover_accepted = 0x0;
	rep->ib_rep_params_1.end_to_end_flow_control = 0x0;
	rep->ib_rep_params_2.rnr_retry_count = 0x7;
	rep->ib_rep_params_2.srq = 0x0;
	rep->ib_rep_params_2.reserved = 0x0;
	rep->local_ca_guid = 0x02155dfffe240104;
}

uint16_t IpHdrChecksum(struct iphdr *hdr)
{
	union _iphdr
	{
		struct iphdr hdr;
		uint16_t data[10];
	};

	union _iphdr ip;

	// Copy data into payload
	memcpy(ip.data, hdr, 20);

	uint32_t Checksum = 0;

	for (int i = 0; i < 10; i++)
	{
		if (i == 5)
		{
			continue;
		}
		Checksum += ip.data[i];
	}

	Checksum = (Checksum & 0xFFFF) + ((Checksum & 0xFFFF0000) >> 16);
	Checksum = Checksum ^ 0x0000FFFF;

	return (uint16_t)Checksum;
}

int InsertIcrc(unsigned char *buffer, int buflen)
{
	uint32_t icrc = calc_icrc32(buffer, buflen);
	uint32_t *ptr = (uint32_t *)&buffer[buflen - 4];
	*ptr = icrc;
}

/// @brief Check IP Header calculation function
/// @return
uint16_t IpHdrCheck()
{
	uint16_t ReferenceCrc, CalulatedCrc;

	// Check IP CRC
	ReferenceCrc = (ExampleIPhdr[10] + (ExampleIPhdr[11] << 8));
	CalulatedCrc = IpHdrChecksum((struct iphdr *)&ExampleIPhdr[0]);
	if (ReferenceCrc != CalulatedCrc)
	{
		printf("1: Checksum error ref %x != %x\n", ReferenceCrc, CalulatedCrc);
		return 1;
	}

	ReferenceCrc = (connect_req_packet_bytes[24] + (connect_req_packet_bytes[25] << 8));
	CalulatedCrc = IpHdrChecksum((struct iphdr *)&connect_req_packet_bytes[14]);
	if (ReferenceCrc != CalulatedCrc)
	{
		printf("2: Checksum error ref %x != %x\n", ReferenceCrc, CalulatedCrc);
		return 1;
	}

	ReferenceCrc = (connect_reply_packet_bytes[24] + (connect_reply_packet_bytes[25] << 8));
	CalulatedCrc = IpHdrChecksum((struct iphdr *)&connect_reply_packet_bytes[14]);
	if (ReferenceCrc != CalulatedCrc)
	{
		printf("3: Checksum error ref %x != %x\n", ReferenceCrc, CalulatedCrc);
		return 1;
	}

	return 0;
}

/// @brief Check Icrc calculation
/// @return 0 is succes
uint16_t IcrcCheck()
{
	// Check iCRC calculation
	uint32_t crc = calc_icrc32((char *)connect_req_packet_bytes, sizeof(connect_req_packet_bytes));
	uint32_t *ptr = (uint32_t *)&connect_req_packet_bytes[sizeof(connect_req_packet_bytes) - 4];
	if (*ptr != crc)
	{
		printf("1: iCRC Checksum error ref %x != %x\n", *ptr, crc);
		// return 1;
	}

	// Check iCRC calculation
	crc = calc_icrc32(connect_reply_packet_bytes, sizeof(connect_reply_packet_bytes));
	ptr = (uint32_t *)&connect_reply_packet_bytes[sizeof(connect_reply_packet_bytes) - 4];
	if (*ptr != crc)
	{
		printf("2: iCRC Checksum error ref %x != %x\n", *ptr, crc);
		// return 1;
	}

	// Check CRC insertion
	unsigned char buffer[sizeof(connect_req_packet_bytes)];
	memcpy(&buffer, connect_req_packet_bytes, sizeof(connect_req_packet_bytes) - 4);
	InsertIcrc(buffer, sizeof(buffer));

	for (int i = sizeof(connect_req_packet_bytes) - 4, n = 0; i < sizeof(connect_req_packet_bytes); i++)
	{
		if (connect_req_packet_bytes[i] != buffer[i])
		{
			printf("3: iCRC Checksum error ref loc = %d %x != %x\n", i, connect_req_packet_bytes[i], buffer[i]);
		}
	}
	return 0;
}

/// @brief Perform function checks
/// @return
uint16_t Checking()
{
	if (IpHdrCheck() != 0)
		return 1;
	if (IcrcCheck() != 0)
		return 2;
	return 0;
}

int Process(struct roce_input_msg *roce_in, int len)
{
	char *buffer = (char *)roce_in;
	char data_out[MAXLINE];

	// Swap MAC
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	memcpy(src_mac, roce_in->ethh.h_source, sizeof(roce_in->ethh.h_source));
	memcpy(dst_mac, roce_in->ethh.h_dest, sizeof(roce_in->ethh.h_dest));
	memcpy(roce_in->ethh.h_source, dst_mac, sizeof(dst_mac));
	memcpy(roce_in->ethh.h_dest, src_mac, sizeof(src_mac));

	int header = 28;

	uint32_t src_addr = roce_in->iph.daddr;
	uint32_t dst_addr = roce_in->iph.saddr;

	ib_send_rep(&buffer[42], data_out);
	memcpy(&buffer[42], data_out, 280);

	roce_in->iph.saddr = src_addr;
	roce_in->iph.daddr = dst_addr;

	uint32_t src_port = roce_in->udph.uh_dport;
	uint32_t dst_port = roce_in->udph.uh_sport;
	// roce_in->udph.uh_sport = dst_port;
	// roce_in->udph.uh_dport = src_port;
	roce_in->udph.check = 0;
	roce_in->iph.protocol = 0x11;
	return 0;
}

void payload(unsigned char *buffer, int buflen, char *name)
{
	int i = 0;
	unsigned char *data = (buffer);
	fprintf(log_txt, "\nData %s, with size of %d bytes\n", name, buflen);

	fprintf(log_txt, "\n %.4x :", i);
	int remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
	for (i = 0; i < remaining_data; i++)
	{
		if (i != 0 && i % 16 == 0)
			fprintf(log_txt, "\n %.4x :", i);
		fprintf(log_txt, " %.2X ", data[i]);
	}

	fprintf(log_txt, "\n");
}

void ethernet_header(unsigned char *buffer, int buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	fprintf(log_txt, "\nEthernet Header\n");

	fprintf(log_txt,"\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	fprintf(log_txt,"\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	fprintf(log_txt,"\t|-Protocol		: %d\n",eth->h_proto);

	// Copy addres into variable
	memcpy(dest_mac,eth->h_dest,sizeof(eth->h_dest));
	memcpy(src_mac,eth->h_source,sizeof(eth->h_source));
}

void ip_header(unsigned char *buffer, int buflen)
{
	struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

	iphdrlen = ip->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;

	fprintf(log_txt, "\nIP Header\n");
	fprintf(log_txt, "\t|-Version              : %d\n", (unsigned int)ip->version);
	fprintf(log_txt, "\t|-Internet Header Len : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
	fprintf(log_txt, "\t|-Type Of Service     : %d\n", (unsigned int)ip->tos);
	fprintf(log_txt, "\t|-Total Length        : %d  Bytes\n", ntohs(ip->tot_len));
	fprintf(log_txt, "\t|-Identification      : %d\n", ntohs(ip->id));
	fprintf(log_txt, "\t|-Time To Live	      : %d\n", (unsigned int)ip->ttl);
	fprintf(log_txt, "\t|-Protocol 	          : %d\n", (unsigned int)ip->protocol);
	fprintf(log_txt, "\t|-Header Checksum     : %d\n", ntohs(ip->check));
	fprintf(log_txt, "\t|-Source IP           : %s\n", inet_ntoa(source.sin_addr));
	fprintf(log_txt, "\t|-Destination IP      : %s\n", inet_ntoa(dest.sin_addr));

}

void ib_header(unsigned char *buffer, int buflen)
{
	struct ib_base_transport_header *ibth = (struct ib_base_transport_header *)(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

	fprintf(log_txt, "\n*************************Infiniband packet*******************");
	fprintf(log_txt, "\n Infiniband base transport header\n");
	fprintf(log_txt, "\t|-Opcode            : %d\n", ibth->opcode);
	fprintf(log_txt, "\t|-tver          	: %x\n", ibth->se__m__padcnt__tver);
	fprintf(log_txt, "\t|-Partition Key    	: %d\n", ntohs(ibth->pkey));
	fprintf(log_txt, "\t|-Destination Qp    : %x\n", ntohl(ibth->dest_qp));
	fprintf(log_txt, "\t|-Acknowledge Req   : %x\n", ibth->ack__req);
	fprintf(log_txt, "\t|-Packet Seq Nr   	: %d\n", ((ibth->ack__psn) >> 16) & 0xFF + ((ibth->ack__psn) >> 8) & 0xFF + ((ibth->ack__psn) >> 0) & 0xFF);
	fprintf(log_txt, "*****************************************************************\n\n\n");
}

void ib_extended_transport_header(unsigned char *buffer, int buflen)
{
	struct ib_datagram_extended_transport_header *bth = (struct ib_datagram_extended_transport_header *)(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct ib_base_transport_header));

	fprintf(log_txt, "\n*************************Infiniband packet*******************");
	fprintf(log_txt, "\n Infiniband datagram extended_transport header\n");
	fprintf(log_txt, "\t|-Queue key          : %x\n", ntohl(bth->qkey));
	fprintf(log_txt, "\t|-Source Queue Pair  : %x\n", ntohl(bth->src_qp));
	fprintf(log_txt, "*****************************************************************\n\n\n");
}

void ib_request(unsigned char *buffer, int buflen)
{
	struct ib_req *req = (struct ib_req *)(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(ib_header) + sizeof(struct ib_datagram_extended_transport_header) + sizeof(struct ib_management_datagram_field));

	fprintf(log_txt, "\n*************************Infiniband packet*******************");
	fprintf(log_txt, "\n Connect request\n");
	fprintf(log_txt, "\t|-Local Communication ID   : %x\n", ntohs(req->local_comm_id));
	fprintf(log_txt, "*****************************************************************\n\n\n");
}

void ib_mad_header(unsigned char *buffer, int buflen)
{
	struct ib_management_datagram_field *madh = (struct ib_management_datagram_field *)(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header));

	fprintf(log_txt, "\n*************************Infiniband packet*******************");
	fprintf(log_txt, "\n MAD Header - Common Management Datagram\n");
	fprintf(log_txt, "\t|-Base version      : %x\n", (madh->base_version));
	fprintf(log_txt, "\t|-Managment Class   : %x\n", (madh->mgmt_class));
	fprintf(log_txt, "\t|-Class Version     : %x\n", (madh->class_version));
	fprintf(log_txt, "\t|-Method            : %x\n", madh->ib_mad_params.method);
	fprintf(log_txt, "\t|-Response          : %x\n", madh->ib_mad_params.r);
	fprintf(log_txt, "\t|-Status            : %x\n", ntohl(madh->status));
	fprintf(log_txt, "\t|-Class Specific    : %x\n", ntohl(madh->class_specific));
	fprintf(log_txt, "\t|-Transaction ID    : %lx\n", be64toh(madh->transaction_id));
	fprintf(log_txt, "\t|-Attribute ID      : %x\n", ntohs(madh->attribute_id));
	fprintf(log_txt, "\t|-Attribute Modifier: %d\n", ntohs(madh->attribute_modifier));
	fprintf(log_txt, "*****************************************************************\n\n\n");

	if (ntohs(madh->attribute_id) == 0x10)
	{
		ib_request(buffer, buflen);
		ib_conn_req = 1;
		ib++;
	}
}

void udp_header(unsigned char *buffer, int buflen)
{
	// fprintf(log_txt, "\n*************************UDP Packet******************************");
	ethernet_header(buffer, buflen);
	ip_header(buffer, buflen);
	fprintf(log_txt, "\nUDP Header\n");

	struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
	fprintf(log_txt, "\t|-Source Port    	: %d\n", ntohs(udp->source));
	fprintf(log_txt, "\t|-Destination Port	: %d\n", ntohs(udp->dest));
	fprintf(log_txt, "\t|-UDP Length      	: %d\n", ntohs(udp->len));
	fprintf(log_txt, "\t|-UDP Checksum   	: %d\n", ntohs(udp->check));

	// payload(buffer,buflen);

	fprintf(log_txt, "*****************************************************************\n\n\n");
	if (ntohs(udp->dest) == PORT)
	{
		ib_header(buffer, buflen);
		ib_extended_transport_header(buffer, buflen);
		ib_mad_header(buffer, buflen);
	}
}

void data_process(unsigned char *buffer, int buflen)
{
	struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	struct udphdr *ud = (struct udphdr *)(buffer + +sizeof(struct ethhdr) + +sizeof(struct iphdr));
	static int total = 0;
	static int tcp, udp, other;

	total++;
	/* we will se UDP Protocol only*/
	switch (ip->protocol) // see /etc/protocols file
	{

	case 1:
	    ++icmp;
		break;
	case 6:
		++tcp;
		// tcp_header(buffer,buflen);
		break;

	case 17:
		++udp;
		if (ntohs(ud->dest) == PORT)
		{
			// Only process IB packets
			udp_header(buffer, buflen);
		}
		break;

	default:
		++other;
	}
	printf("TCP: %d  UDP: %d  Other: %d  : IB %d  ICMP : %d Toatl: %d  \r", tcp, udp, other, ib, icmp, total);
}

void get_eth_index(int sock_raw)
{
	memset(&ifreq_i, 0, sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name, INTF, IFNAMSIZ - 1);

	if ((ioctl(sock_raw, SIOCGIFINDEX, &ifreq_i)) < 0)
		printf("error in index ioctl reading");

	printf("index=%d\n", ifreq_i.ifr_ifindex);
}

void get_mac(int sock_raw)
{
	memset(&ifreq_c, 0, sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name, INTF, IFNAMSIZ - 1);

	if ((ioctl(sock_raw, SIOCGIFHWADDR, &ifreq_c)) < 0)
		printf("error in SIOCGIFHWADDR ioctl reading");

	printf("Mac= %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]));

	printf("ethernet packaging start ... \n");

	struct ethhdr *eth = (struct ethhdr *)(sendbuff);
	// eth->h_dest[0] = eth->h_source[0];
	// eth->h_dest[1] = eth->h_source[1];
	// eth->h_dest[2] = eth->h_source[2];
	// eth->h_dest[3] = eth->h_source[3];
	// eth->h_dest[4] = eth->h_source[4];
	// eth->h_dest[5] = eth->h_source[5];

	eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
	eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
	eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
	eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
	eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
	eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

	memcpy(eth->h_dest,src_mac,sizeof(eth->h_dest));

	// eth->h_dest[0] = DESTMAC0;
	// eth->h_dest[1] = DESTMAC1;
	// eth->h_dest[2] = DESTMAC2;
	// eth->h_dest[3] = DESTMAC3;
	// eth->h_dest[4] = DESTMAC4;
	// eth->h_dest[5] = DESTMAC5;

	eth->h_proto = htons(ETH_P_IP); // 0x800

	printf("ethernet packaging done.\n");

	total_len += sizeof(struct ethhdr);
}

void get_data()
{
	static int len = 10;

	for (int i = 0; i < len; i++)
	{
		sendbuff[total_len++] = 0xAA;
	}
	sendbuff[total_len++] = 0xBB;

	len += 5;
}

void get_udp(unsigned char *buffer, int buflen)
{
	struct udphdr *uh = (struct udphdr *)(sendbuff + sizeof(struct iphdr) + sizeof(struct ethhdr));

	uh->source = htons(SPORT);
	uh->dest = htons(PORT);
	uh->check = 0;

	total_len += sizeof(struct udphdr);
	// get_data();

	// int HeaderSize = sizeof(struct iphdr) + sizeof(struct ethhdr);
	for (int i = 0; i < (buflen); i++)
	{
		sendbuff[total_len++] = buffer[i];
	}
	uh->len = htons((total_len - sizeof(struct iphdr) - sizeof(struct ethhdr)));
}

unsigned short checksum(unsigned short *buff, int _16bitword)
{
	unsigned long sum;
	for (sum = 0; _16bitword > 0; _16bitword--)
		sum += htons(*(buff)++);
	do
	{
		sum = ((sum >> 16) + (sum & 0xFFFF));
	} while (sum & 0xFFFF0000);

	return (~sum);
}

void get_ip(int sock_raw, unsigned char *buffer, int buflen)
{
	memset(&ifreq_ip, 0, sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name, INTF, IFNAMSIZ - 1);
	if (ioctl(sock_raw, SIOCGIFADDR, &ifreq_ip) < 0)
	{
		printf("error in SIOCGIFADDR \n");
	}

	printf("%s\n", inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));

	/****** OR
		int i;
		for(i=0;i<14;i++)
		printf("%d\n",(unsigned char)ifreq_ip.ifr_addr.sa_data[i]); ******/

	struct iphdr *iph = (struct iphdr *)(sendbuff + sizeof(struct ethhdr));
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16;
	iph->id = htons(10201);
	iph->ttl = 64;
	iph->protocol = 17;
	iph->saddr = inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));
	iph->daddr = source.sin_addr.s_addr;	//   inet_addr("destination_ip"); // put destination IP address
	total_len += sizeof(struct iphdr);
	get_udp(buffer, buflen);

	iph->tot_len = htons(total_len - sizeof(struct ethhdr));
	iph->check = htons(checksum((unsigned short *)(sendbuff + sizeof(struct ethhdr)), (sizeof(struct iphdr) / 2)));
}

int SendRoce(unsigned char *buffer, int buflen)
{
	int sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

	total_len = 0;

	if (sock_raw == -1)
		printf("error in socket");

	sendbuff = (unsigned char *)malloc(1500); // increase in case of large data.Here data is --> AA  BB  CC  DD  EE
	memset(sendbuff, 0, 1500);

	get_eth_index(sock_raw); // interface number
	get_mac(sock_raw);
	get_ip(sock_raw, buffer, buflen);

	struct ethhdr *eth = (struct ethhdr *)(buffer);

	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
	sadr_ll.sll_halen = ETH_ALEN;

	memcpy(sadr_ll.sll_addr,src_mac,sizeof(sadr_ll.sll_addr));

	// sadr_ll.sll_addr[0] = DESTMAC0;
	// sadr_ll.sll_addr[1] = DESTMAC1;
	// sadr_ll.sll_addr[2] = DESTMAC2;
	// sadr_ll.sll_addr[3] = DESTMAC3;
	// sadr_ll.sll_addr[4] = DESTMAC4;
	// sadr_ll.sll_addr[5] = DESTMAC5;

	// InserCrc
	InsertIcrc(sendbuff, total_len);

	payload(sendbuff, total_len, "Tx Ethernet Data");

	printf("sending...\n");
	send_len = sendto(sock_raw, sendbuff, total_len, 0, (const struct sockaddr *)&sadr_ll, sizeof(struct sockaddr_ll));
	if (send_len < 0)
	{
		printf("error in sending....sendlen=%d....errno=%d\n", send_len, errno);
		return -1;
	}
}

int raw_socket()
{

	int sock_r, saddr_len, buflen;

	unsigned char *buffer = (unsigned char *)malloc(65536);
	memset(buffer, 0, 65536);

	printf("starting .... \n");

	sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_r < 0)
	{
		printf("error in socket\n");
		return -1;
	}

	while (1)
	{
		saddr_len = sizeof saddr;

		memset(buffer, 0, 65536);
		buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);

		if (buflen < 0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		fflush(log_txt);

		// Process incomming data
		data_process(buffer, buflen);

		if (ib_conn_req == 1)
		{
			ib_conn_req = 0;
			ib_send_rep(&buffer[42], data_out);
			payload((unsigned char *)data_out, 280, "payload");
			SendRoce(data_out, 280);
			fflush(log_txt);

			// Compare payload with ref
			for (int i = 0, n = 0; i < sizeof(connect_reply_payload_packet_bytes); i++)
			{
				if (connect_reply_payload_packet_bytes[i] != (unsigned char)data_out[i])
				{
					printf("[%3d - %.3X] %.2X %.2X\n", i, i + 42, connect_reply_payload_packet_bytes[i], (unsigned char)data_out[i]);
				}
			}
		}
	}

	// close(sock_r);// use signals to close socket
}

// Driver code
int main()
{
	int sockfd;
	char buffer[MAXLINE];
	char data_out[MAXLINE];
	struct sockaddr_in servaddr, cliaddr;
	struct roce_input_msg *roce_in = (struct roce_input_msg *)buffer;

	initCrc();

	if (Checking() != 0)
	{
		return 0;
	}

	log_txt = fopen("log.txt", "w");
	if (!log_txt)
	{
		printf("unable to open log.txt\n");
		return -1;
	}

	raw_socket();

	return 0;
}
