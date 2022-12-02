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

char connect_req_packet_bytes[] = {
	0x64, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
	0x80, 0x00, 0x00, 0x0c, 0x80, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x01, 0x07, 0x02, 0x03,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0xd5, 0x67, 0x2a, 0x51, 0x00, 0x10, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x51, 0x2a, 0x67, 0xd5,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x06, 0x1c, 0x06, 0x02, 0x15, 0x5d, 0xff,
	0xfe, 0x01, 0x02, 0x0d, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x01,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0,
	0xd6, 0x36, 0x75, 0xa7, 0xff, 0xff, 0x37, 0xf0,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
	0xc0, 0xa8, 0x01, 0x66, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
	0xc0, 0xa8, 0x01, 0x65, 0x14, 0xa6, 0x40, 0x00,
	0x00, 0x40, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x40, 0x8d, 0xe2, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc0, 0xa8, 0x01, 0x66, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc0, 0xa8, 0x01, 0x65, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xbf, 0x0a, 0x9d, 0xe4};

struct ib_mad_params
{
	uint8_t method : 7;
	uint8_t r : 1;

} __attribute__((packed));

struct ib_rep_params_1
{
	uint8_t end_to_end_flow_control : 1;
	uint8_t failover_accepted : 2;
	uint8_t target_ack_delay : 5;
} __attribute__((packed));

struct ib_rep_params_2
{
	uint8_t reserved : 4;
	uint8_t srq : 1;
	uint8_t rnr_retry_count : 3;
} __attribute__((packed));

struct ib_req_params_1
{
	uint32_t local_qpn : 24;
	uint32_t resp_resources : 8;
} __attribute__((packed));

struct ib_req_params_2
{
	uint32_t local_eecn : 24;
	uint32_t initiator_depth : 8;
} __attribute__((packed));

struct ib_req_params_3
{
	uint32_t remote_eecn : 24;
	uint32_t remote_cm_response_timeout : 5;
	uint32_t transport_service_tyoe : 2;
	uint32_t end_to_end_flow_control : 1;
} __attribute__((packed));

struct ib_req_params_4
{
	uint32_t starting_psn : 24;
	uint32_t local_cm_response_timeout : 5;
	uint32_t retry_count : 3;
} __attribute__((packed));

struct ib_req_params_5
{
	uint32_t partition_key : 16;
	uint32_t path_packet_payload_mtu : 4;
	uint32_t rdc_exists : 1;
	uint32_t rnr_retry_count : 3;
	uint32_t max_cm_retries : 4;
	uint32_t srq : 1;
	uint32_t reserved : 3;
} __attribute__((packed));

struct ib_req_params_6
{
	uint32_t primary_flow_label : 20;
	uint32_t reserved : 6;
	uint32_t primary_packet_rate : 6;
} __attribute__((packed));

struct ib_req_params_7
{
	uint32_t primary_traffic_class : 8;
	uint32_t primary_hop_limit : 8;
	uint32_t primary_sl : 4;
	uint32_t primary_subnet_local : 1;
	uint32_t reserved_1 : 3;
	uint32_t primary_local_ack_timeout : 5;
	uint32_t reserved_2 : 3;
} __attribute__((packed));

struct ib_req_params_8
{
	uint32_t alternate_flow_label : 20;
	uint32_t reserved : 6;
	uint32_t alternate_packet_rate : 6;
} __attribute__((packed));

struct ib_req_params_9
{
	uint32_t alternate_traffic_class : 8;
	uint32_t alternate_hop_limit : 8;
	uint32_t alternate_sl : 4;
	uint32_t alternate_subnet_local : 1;
	uint32_t reserved_1 : 3;
	uint32_t primary_local_ack_timeout : 5;
	uint32_t reserved_2 : 3;
} __attribute__((packed));

/** An Infiniband Base Transport Header */
struct ib_base_transport_header
{
	/* Opcode */
	uint8_t opcode;
	/* Transport header version, pad count, migration and solicitation */
	uint8_t se__m__padcnt__tver;
	/* Partition key */
	uint16_t pkey;
	/* Destination queue pair */
	uint32_t dest_qp;
	/* Packet sequence number and acknowledge request */
	uint32_t ack__psn;
} __attribute__((packed));

/* An Infiniband Datagram Extended Transport Header */
struct ib_datagram_extended_transport_header
{
	/* Queue key */
	uint32_t qkey;
	/* Source queue pair */
	uint32_t src_qp;
} __attribute__((packed));

/** An Infiniband Management Datagram Field (MAD) */
struct ib_management_datagram_field
{
	/* Version of MAD base format. */
	uint8_t base_version;
	/* Class of operation. */
	uint8_t mgmt_class;
	/* Version of MAD class-specific format, shall be 1 unless otherwise specified. */
	uint8_t class_version;
	/* [7] Response bit (r), should be 1 for a response message. */
	/* [0:6] Method to perform based on the management class. */
	struct ib_mad_params ib_mad_params;
	// uint8_t test;
	/* Code indicating status of operation. */
	uint16_t status;
	/* This field is reserved for the Subnet Management class. */
	uint16_t class_specific;
	/* Transaction identifier, set to 0 if field is unused by management class. */
	uint64_t transaction_id;
	/* [31:16] Defines objects being operated on by a management class, set to 0 if unused. */
	/* [15:0] Reserved */
	uint32_t attribute_id;
	/* Provides further scope to the attributes. Usage is determined by the managment class and attribute. Set field to 0 if it is not used by the management class and attribute. */
	uint32_t attribute_modifier;
} __attribute__((packed));

/** An Infiniband Reply to Request message (REP) */
struct ib_rep
{
	/* Identifier that uniquely identifies this connection from the sender's point of view. */
	uint32_t local_comm_id;
	/* An identifier that uniquely indentifies this connection from the recipient's point of view. */
	uint32_t remote_comm_id;
	/* The Q_key for the QP specified by the local QPN. */
	uint32_t local_q_key;
	/* [31:8] The QPN of the message sender's QP on which the channel is to be established. */
	/* [7:0]  Reserved */
	uint32_t local_qpn;
	/* [31:8] The EE Context Number for the message sender's end of the RD channel. */
	/* [7:0]  Reserved */
	uint32_t local_eecn;
	/* [7:0] The transport packet sequence number at which the remote node shall begin transmitting. */
	/* [7:0] Reserved */
	uint32_t starting_psn;
	/* The maximum number of outstanding RDMA read/atomic operations the sender will support from the remote QP/EEC. Value may be zero. */
	uint8_t resp_resources;
	/* The maximum number of outstanding RDMA read/atomic operations the sender will have to the remote QP/EEC. Value may be zero. Number should not exceed the Responder Resources given in REQ. */
	uint8_t initiator_depth;
	/* [7:3] Tarcket ACK delay, maximum expected time interval between target CA's reception of a message and the transmission of the associated ACK or NAK. */
	/* [2:1] Failover accepted, indicates whether the target of the REQ accepted or rejected the Alternate port address contained in the REQ. By send the REP, the target accepts the connection request, but it may still reject the proposed failover port. */
	/* [0] End-to-End flow control, signifies whether the local CA acutally implements End-to-End flow control. */
	struct ib_rep_params_1 ib_rep_params_1;
	/* [7:5] The total number of times that the REQ or REP send while the receiver to retry RNR NAK errors before posting a completion error. */
	/* [4] SRQ, should be 1 if SRQ exists. */
	/* [3:0] Reserved */
	struct ib_rep_params_2 ib_rep_params_2;
	uint64_t local_ca_guid;
} __attribute__((packed));

/** An Infiniband Request message (REQ) */
struct ib_req
{
	uint32_t local_comm_id;
	uint32_t reserved_1;
	uint64_t service_id;
	uint64_t local_ca_guid;
	uint32_t reserved_2;
	uint32_t q_key;
	struct ib_req_params_1 ib_req_params_1;
	struct ib_req_params_2 ib_req_params_2;
	struct ib_req_params_3 ib_req_params_3;
	struct ib_req_params_4 ib_req_params_4;
	struct ib_req_params_5 ib_req_params_5;
	uint16_t primary_local_port_lid;
	uint16_t primary_remote_port_lid;
	uint64_t primary_local_port_gid_1;
	uint64_t primary_local_port_gid_2;
	uint64_t primary_remote_port_gid_1;
	uint64_t primary_remote_port_gid_2;
	struct ib_req_params_6 ib_req_params_6;
	struct ib_req_params_7 ib_req_params_7;
	uint16_t alternate_local_port_lid;
	uint16_t alternate_remote_port_lid;
	uint64_t alternate_local_port_gid_1;
	uint64_t alternate_local_port_gid_2;
	uint64_t alternate_remote_port_gid_1;
	uint64_t alternate_remote_port_gid_2;
	struct ib_req_params_8 ib_req_params_8;
	struct ib_req_params_9 ib_req_params_9;
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

char ExampleIPhdr[] = {
	0x45, 0x00, 0x01, 0x34, 0xb6, 0xaf, 0x40, 0x00,
	0x40, 0x11, 0xfe, 0xed, 0xc0, 0xa8, 0x01, 0x66,
	0xc0, 0xa8, 0x01, 0x65};

uint16_t IpHdrChecksum(struct iphdr *hdr)
{
	union _iphdr
	{
		struct iphdr hdr;
		uint16_t data[10];
	};

	union _iphdr ip;

    // Copy data into payload
	memcpy(ip.data,hdr,20);


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

uint16_t Checking()
{
	// Check IP CRC
	uint16_t *Crc = &ExampleIPhdr[5 * 2];
	uint16_t CalulatedCrc = IpHdrChecksum(&ExampleIPhdr[0]);
	if (*Crc != CalulatedCrc)
	{
		printf("Checksum error %x != %x\n", *Crc, CalulatedCrc);
		return 1;
	}

	return 0;
}

// cm_t cm;
// p_cm_t p_cm = &cm;

// Report_ib_base_transport_header(&connect_req_packet_bytes[0]);
// Report_ib_extended_transport_header(&connect_req_packet_bytes[sizeof(struct ib_base_transport_header)]);
// Report_ib_management_datagram_field(&connect_req_packet_bytes[sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header)]);

// Driver code
int main()
{
	int sockfd;
	char buffer[MAXLINE];
	char data_out[MAXLINE];
	char *hello = "Hello from server";
	struct sockaddr_in servaddr, cliaddr;
	struct roce_input_msg *roce_in = (struct roce_input_msg *)buffer;

	if (Checking() != 0) {
		return;
	}

	initCrc();

	//  Creating socket file descriptor
	//if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
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
		process_ip(&buffer);
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
