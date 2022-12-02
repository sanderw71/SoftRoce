#include "udp_server.h"
// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/udp.h>  //Provides declarations for tcp header
#include <netinet/ip.h>	  //Provides declarations for ip header
#include "crc32.h"
#include "ib.h"

#include "ref_packets.h"

// ROCE Server port
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

struct roce_input_msg
{
	struct iphdr iph;
	struct udphdr udph;
	char payload[MAXLINE];
} __attribute__((packed));

void Report_ib_base_transport_header(char *_data)
{
	struct ib_base_transport_header *bth;

	bth = (void *)_data;

	printf("Report_ib_base_transport_header\n");
	printf("Opcode                 %-10d\n", bth->opcode);
	printf("se__m__padcnt__tver    %-10d\n", bth->se__m__padcnt__tver);
	printf("pkey                   %-10d\n", bth->pkey);
	printf("dest_qp                0x%x\n", ntohl(bth->dest_qp));
	printf("psn                    %-10d\n", (ntohl((bth->ack__psn)) & 0xFFFFFF));
}

void Report_ib_extended_transport_header(char *_data)
{
	struct ib_datagram_extended_transport_header *bth;

	bth = (void *)_data;

	printf("\nib_datagram_extended_transport_header\n");
	printf("qkey                  0x%x\n", ntohl(bth->qkey));
	printf("src_qp                0x%x\n", ntohl(bth->src_qp));

#ifdef raw
	printf("raw: ");
	for (int i = 0; i < sizeof(struct ib_datagram_extended_transport_header); i++)
	{
		printf("%2X ", (unsigned char)_data[i]);
	}
#endif
}

void Report_ib_management_datagram_field(char *_data)
{
	struct ib_management_datagram_field *bth;

	bth = (void *)_data;

	printf("\nReport_ib_management_datagram_field\n");
	printf("Method                 0x%x\n", bth->ib_mad_params.method);
	printf("R                      0x%x\n", bth->ib_mad_params.r);
	printf("Class version          0x%x\n", (bth->class_version));
	printf("Management class       0x%x\n", (bth->mgmt_class));
	printf("Base version	       0x%x\n", (bth->base_version));
	printf("Class specific         0x%x\n", ntohl(bth->class_specific));
	printf("Status                 0x%x\n", ntohl(bth->status));
	printf("Transaction ID         0x%lx\n", be64toh(bth->transaction_id));
	printf("Attribute ID           0x%x\n", ntohl(bth->attribute_id));
	printf("Attribute modifier     0x%x\n", ntohl(bth->attribute_modifier));
}

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

	bth_out->opcode = bth_in->opcode;
	bth_out->se__m__padcnt__tver = bth_in->se__m__padcnt__tver;
	bth_out->pkey = bth_in->pkey;
	bth_out->dest_qp = bth_in->dest_qp;
	bth_out->ack__psn = bth_psn++;

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
	rep->starting_psn = ntohl(0xF);
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

int process_roce(char *buffer, int len)
{
	Report_ib_base_transport_header(&buffer[0]);
	Report_ib_extended_transport_header(&buffer[sizeof(struct ib_base_transport_header) + 0]);
	Report_ib_management_datagram_field(&buffer[sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header) + 0]);

	uint32_t *ptr = (uint32_t *)&buffer[len - 4];
	printf("\nCrc = %x\n", *ptr);
	return 0;
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

int process_ip(struct roce_input_msg *msg)
{
	printf("source addr   %x\n", ntohl(msg->iph.saddr));
	printf("dest   addr   %x\n", ntohl(msg->iph.daddr));
	printf("len           %d\n", ntohs(msg->iph.tot_len));
	printf("checksum      %x\n", msg->iph.check);
	printf("calc checksum %x\n", IpHdrChecksum(&msg->iph));
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
		return 1;
	}

	// Check iCRC calculation
	crc = calc_icrc32(connect_reply_packet_bytes + 14, sizeof(connect_reply_packet_bytes));
	ptr = (uint32_t *)&connect_reply_packet_bytes[sizeof(connect_reply_packet_bytes) - 4];
	if (*ptr != crc)
	{
		printf("2: iCRC Checksum error ref %x != %x\n", *ptr, crc);
		return 1;
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

// Report_ib_base_transport_header(&connect_req_packet_bytes[0]);
// Report_ib_extended_transport_header(&connect_req_packet_bytes[sizeof(struct ib_base_transport_header)]);
// Report_ib_management_datagram_field(&connect_req_packet_bytes[sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header)]);

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

	//  Creating socket file descriptor
	// if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
	{
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	// Filling server information
	servaddr.sin_family = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PORT);

	// Bind the socket with the server address
	if (bind(sockfd, (const struct sockaddr *)&servaddr,
			 sizeof(servaddr)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	printf("Server raw listining on port  : %d\n", PORT);

	while (1 == 1)
	{
		int len = sizeof(cliaddr); // len is value/result
		int n = recvfrom(sockfd, (char *)buffer, MAXLINE,
						 MSG_WAITALL, (struct sockaddr *)&cliaddr,
						 &len);

		struct iphdr *iph = (struct iphdr *)buffer;
		struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ip));

		if (ntohs(udph->uh_dport) != PORT)
		{
			printf(".\n");
			continue;
		}

		printf("Message received with length of : %d\n", n);
		printf("port        %d\n", ntohs(roce_in->udph.uh_dport));
		printf("source addr %x\n", ntohl(roce_in->iph.saddr));
		printf("dest   addr %x\n", ntohl(roce_in->iph.daddr));
		printf("len         %d\n", ntohs(roce_in->iph.tot_len));

#ifdef raw
		printf("\nIP header: ");
		for (int i = 0; i < 20; i++)
		{
			printf("%2X ", (unsigned char)buffer[i]);
		}
		printf("\nUDP header: ");
		for (int i = 20; i < 20 + 8; i++)
		{
			printf("%2X ", (unsigned char)buffer[i]);
		}
#endif

		int header = 28;
		process_ip(roce_in);
		process_roce(&buffer[header], len - 28);

		uint32_t src_addr = roce_in->iph.daddr;
		uint32_t dst_addr = roce_in->iph.saddr;

		ib_send_rep(&buffer[28], data_out);
		memcpy(&buffer[28], data_out, 280);

		roce_in->iph.saddr = src_addr;
		roce_in->iph.daddr = dst_addr;

		uint32_t src_port = roce_in->udph.uh_dport;
		uint32_t dst_port = roce_in->udph.uh_sport;
		// roce_in->udph.uh_sport = dst_port;
		// roce_in->udph.uh_dport = src_port;
		roce_in->udph.check = 0;
		roce_in->iph.protocol = 0x11;

		for (int i = 0; i < 280 + HDR_SIZE; i++)
		{
			printf("%.2x ", (unsigned char)buffer[i]);
		}

		// Add crc
		uint32_t crc = calc_icrc32(buffer, n);
		uint32_t *ptr = (uint32_t *)&buffer[n - 4];
		*ptr = crc;

		sendto(sockfd, buffer, 280 + HDR_SIZE - 20, MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);

		printf("\nWaiting for next message.\n");
	}
	return 0;
}
