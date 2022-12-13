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

#include "opcode.h"

#include "net_utils.h"

#define DELAY 0

// ROCE Server port
#define RDMA_PORT 4791
#define MAXLINE 1500

#define IP_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define HDR_SIZE IP_HDR_SIZE + UDP_HDR_SIZE
#define ICRC_SIZE 4

int rdma_send = 0;

void initCrc(void);
uint32_t calc_icrc32(char *data, int len);

// BTH
uint32_t bth_psn = 0;
uint32_t crc = 0xFFFFFFFF;

uint32_t starting_psn = 0;

int icmp, igmp, other, iphdrlen, ib, ib_conn_req, ib_dconn_req;
int ready_to_use = 0;
struct sockaddr saddr;
struct sockaddr_in source, dest;

FILE *log_txt;

char data_out[MAXLINE];
char dest_mac[6];
char src_mac[6];

char ping_buffer[MAXLINE];
char ping_size = 0;

struct sockaddr saddr;
struct sockaddr_in source;
struct sockaddr_in dest;

uint32_t local_qpn = 0;

struct rping_rdma_info
{
	uint64_t buf;
	uint32_t rkey;
	uint32_t size;
};

uint32_t remote_key;
uint64_t virtual_addr;
uint32_t len;

char INTF[12];

/*
 * rping "ping/pong" loop:
 * 	client sends source rkey/addr/len
 *	server receives source rkey/add/len
 *	server rdma reads "ping" data from source
 * 	server sends "go ahead" on rdma read completion
 *	client sends sink rkey/addr/len
 * 	server receives sink rkey/addr/len
 * 	server rdma writes "pong" data to sink
 * 	server sends "go ahead" on rdma write completion
 * 	<repeat loop>
 */

/*
 * These states are used to signal events between the completion handler
 * and the main client or server thread.
 *
 * Once CONNECTED, they cycle through RDMA_READ_ADV, RDMA_WRITE_ADV,
 * and RDMA_WRITE_COMPLETE for each ping.
 */
enum test_state
{
	IDLE = 1,
	CONNECT_REQUEST,
	ADDR_RESOLVED,
	ROUTE_RESOLVED,
	CONNECTED,
	RDMA_READ_ADV,
	RDMA_READ_COMPLETE,
	RDMA_WRITE_ADV,
	RDMA_WRITE_COMPLETE,
	DISCONNECTED,
	ERROR
};
enum test_state state; /* used for cond/signalling */

int SendRoce(unsigned char *buffer, int buflen);

uint8_t LastOpcode;

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

	printf("ib_send_rep : opcode %x\n", bth_in->opcode);
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

	local_qpn = req->ib_req_params_1.local_qpn;
	rep->local_comm_id = ntohl(0x1234);
	rep->remote_comm_id = req->local_comm_id;
	rep->local_q_key = ntohl(0x0);
	rep->local_qpn = req->ib_req_params_1.local_qpn;
	rep->local_eecn = ntohl(0x0);
	rep->starting_psn = 0xF; // ntohl(0xF);
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

void ib_disconnect_rep(char *data_in, char *data_out)
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

	printf("ib_send_rep : opcode %x\n", bth_in->opcode);
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
	mad_out->attribute_id = htons(0x16);
	mad_out->attribute_modifier = mad_in->attribute_modifier;

	rep->local_comm_id = ntohl(0x1234);
	rep->remote_comm_id = req->local_comm_id;
	rep->local_q_key = ntohl(0x0);
	rep->local_qpn = req->ib_req_params_1.local_qpn;
	rep->local_eecn = ntohl(0x0);
	rep->starting_psn = 0xF; // ntohl(0xF);
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

int CheckIcrc(unsigned char *buffer, int buflen)
{
	uint32_t icrc = calc_icrc32(buffer, buflen);
	uint32_t *ptr = (uint32_t *)&buffer[buflen - 4];
	printf("CheckIcrc %x = %x\n", *ptr, icrc);
	return (*ptr == icrc);
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
	int remaining_data = buflen; // - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
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

	fprintf(log_txt, "\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	fprintf(log_txt, "\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	fprintf(log_txt, "\t|-Protocol		: %d\n", eth->h_proto);

	// Copy addres into variable
	memcpy(dest_mac, eth->h_dest, sizeof(eth->h_dest));
	memcpy(src_mac, eth->h_source, sizeof(eth->h_source));
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

uint8_t ib_header(unsigned char *buffer, int buflen)
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

	return ibth->opcode;
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
	struct ib_req *req = (struct ib_req *)(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct ib_base_transport_header) + sizeof(struct ib_datagram_extended_transport_header) + sizeof(struct ib_management_datagram_field));

	fprintf(log_txt, "\n*************************Infiniband packet*******************");
	fprintf(log_txt, "\n Connect request\n");
	fprintf(log_txt, "\t|-Local Communication ID   : %x\n", ntohs(req->local_comm_id));
	fprintf(log_txt, "\t|-Starting PSN             : %x\n", req->ib_req_params_4.starting_psn);
	fprintf(log_txt, "*****************************************************************\n\n\n");

	local_qpn = req->q_key;
	starting_psn = be32toh(req->ib_req_params_4.starting_psn) >> 8;
	printf("Starting psn %x, %d\n", starting_psn, starting_psn);
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

	// ConnectRequest
	if (ntohs(madh->attribute_id) == 0x10)
	{
		printf("\nConnect request\n");
		ib_request(buffer, buflen);
		ib_conn_req = 1;
		ib++;
	}

	// ReadyToUse
	if (ntohs(madh->attribute_id) == 0x14)
	{
		printf("\nReady to use\n");
		ib++;
		ready_to_use = 1;
	}

	// ReadyToUse
	if (ntohs(madh->attribute_id) == 0x15)
	{
		printf("\nDisconnect\n");
		ib_dconn_req = 1;
		ib++;
	}
}

/// @brief Reliable Connection Send Only (incomming message)
/// @param buffer
/// @param buflen
void ib_rc_send_only_rx(unsigned char *buffer, int buflen)
{
	struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

	unsigned char *data = (unsigned char *)(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct ib_base_transport_header));
	unsigned int length = ntohs(udp->len) - sizeof(struct udphdr) - sizeof(struct ib_base_transport_header) - 4;

	fprintf(log_txt, "\n*************************Infiniband packet*******************");
	fprintf(log_txt, "\n ib_rc_send_only_rx\n");
	fprintf(log_txt, "\t|-Lenght                   : %d\n", length);
	fprintf(log_txt, "*****************************************************************\n\n\n");

	payload(data, length, "rc_send_only");

	struct rping_rdma_info *rpinfo = (struct rping_rdma_info *)data;

	remote_key = ntohl(rpinfo->rkey);
	virtual_addr = be64toh(rpinfo->buf);
	len = be32toh(rpinfo->size);

	printf("[ib_rc_send_only_rx] addr = 0x%lx, rkey 0x%x, len = %d\n", virtual_addr, remote_key, len);
}

/// @brief Infiniband Send Only
/// @param buffer
/// @param buflen
/// @param key
/// @param addr
/// @param len
void ib_send_only(unsigned char *buffer, int buflen, uint32_t key, uint64_t addr, uint32_t len)
{
	printf("ib_send_only\n");
	// Output
	struct ib_base_transport_header *bth_out;
	struct rping_rdma_info *rping;

	// Output
	bth_out = (void *)&data_out[0];
	rping = (void *)&data_out[sizeof(struct ib_base_transport_header)];

	rping->rkey = htonl(key);
	rping->buf = htobe64(addr);
	rping->size = htobe32(len);

	// printf("ib_send_ack : opcode %x", 11);
	bth_out->opcode = IBV_OPCODE_RC_SEND_ONLY;
	bth_out->se__m__padcnt__tver = 0x00;
	bth_out->pkey = 0xFFFF;
	bth_out->dest_qp = local_qpn << 8;
	bth_out->ack__req = 0x80;
	bth_out->ack__psn = htonl(starting_psn << 8);
	starting_psn++;

	SendRoce(data_out, sizeof(struct ib_base_transport_header) + sizeof(struct rping_rdma_info) + ICRC_SIZE);
}

void ib_rdma_write_only(unsigned char *buffer, int buflen, uint32_t key, uint64_t addr, uint32_t len)
{
	printf("rdma_write_only len = %d \n", buflen);

	// Output
	struct ib_base_transport_header *bth_out;
	struct ib_rdma_extended_transport_header *reth_out;

	// Output
	bth_out = (void *)&data_out[0];
	reth_out = (void *)&data_out[sizeof(struct ib_base_transport_header)];

	int data = buflen;
	memset(data_out, 0, 12 + 16 + data);

	bth_out->opcode = IBV_OPCODE_RDMA_WRITE_ONLY;
	bth_out->se__m__padcnt__tver = 0x00; // bth_in->se__m__padcnt__tver;
	bth_out->pkey = 0xFFFF;
	bth_out->dest_qp = local_qpn << 8;
	bth_out->ack__req = 0x80;
	bth_out->ack__psn = htonl(starting_psn << 8);
	starting_psn++;

	reth_out->remote_key = htonl(key);
	reth_out->virtual_address = htobe64(addr);
	reth_out->dma_length = htobe32(len);

	memcpy(&data_out[12 + 16], buffer, buflen);

	SendRoce(data_out, 12 + 16 + data + 4);
}

void ib_send_ack(unsigned char *buffer, int buflen)
{
	// Input
	struct ib_base_transport_header *bth_in;

	// Output
	struct ib_base_transport_header *bth_out;
	struct ib_ack_extended_transport_header *aeth_out;

	// Input
	bth_in = (void *)&buffer[0];

	// Output
	bth_out = (void *)&data_out[0];
	aeth_out = (void *)&data_out[sizeof(struct ib_base_transport_header)];

	memset(data_out, 0, 16 + ICRC_SIZE);

	bth_out->opcode = IBV_OPCODE_ACKNOWLEDGE;
	bth_out->se__m__padcnt__tver = bth_in->se__m__padcnt__tver;
	bth_out->pkey = bth_in->pkey;
	bth_out->dest_qp = bth_in->dest_qp;
	bth_out->ack__req = 0;
	bth_out->ack__psn = bth_in->ack__psn;

	aeth_out->Syndrome = 0x1F;
	aeth_out->Message_Sequence_Number = 0x010000; // TODO correct

	SendRoce(data_out, 16 + ICRC_SIZE);
}

void ib_send_rdma_read_response(unsigned char *buffer, int buflen)
{
	// Input
	struct ib_base_transport_header *bth_in;
	struct ib_rdma_extended_transport_header *reth_in;

	// Output
	struct ib_base_transport_header *bth_out;
	struct ib_ack_extended_transport_header *aeth_out;

	// Input
	bth_in = (void *)&buffer[0];
	reth_in = (void *)&buffer[sizeof(struct ib_base_transport_header)];

	// Output
	bth_out = (void *)&data_out[0];
	aeth_out = (void *)&data_out[sizeof(struct ib_base_transport_header)];

	int data = ntohl(reth_in->dma_length);
	memset(data_out, 0, 16 + ICRC_SIZE + data);

	// printf("ib_send_ack : opcode %x", 11);
	bth_out->opcode = IBV_OPCODE_RDMA_READ_RESPONSE_ONLY;
	bth_out->se__m__padcnt__tver = bth_in->se__m__padcnt__tver;
	bth_out->pkey = bth_in->pkey;
	bth_out->dest_qp = bth_in->dest_qp;
	bth_out->ack__req = 0;
	bth_out->ack__psn = bth_in->ack__psn;

	aeth_out->Syndrome = 0x1F;
	aeth_out->Message_Sequence_Number = 0x010000; // TODO correct

	SendRoce(data_out, 16 + ICRC_SIZE + data);
}

void ib_send_rdma_write_response(unsigned char *buffer, int buflen)
{
	// Input
	struct ib_base_transport_header *bth_in;
	struct ib_rdma_extended_transport_header *reth_in;

	// Output
	struct ib_base_transport_header *bth_out;
	struct ib_ack_extended_transport_header *aeth_out;

	// Input
	bth_in = (void *)&buffer[0];

	// Output
	bth_out = (void *)&data_out[0];
	aeth_out = (void *)&data_out[sizeof(struct ib_base_transport_header)];

	memset(data_out, 0, 16 + ICRC_SIZE);

	// printf("ib_send_ack : opcode %x", 11);
	bth_out->opcode = IBV_OPCODE_ACKNOWLEDGE;
	bth_out->se__m__padcnt__tver = bth_in->se__m__padcnt__tver;
	bth_out->pkey = bth_in->pkey;
	bth_out->dest_qp = bth_in->dest_qp;
	bth_out->ack__req = 0;
	bth_out->ack__psn = bth_in->ack__psn;

	aeth_out->Syndrome = 0x1F;
	aeth_out->Message_Sequence_Number = 0x010000; // TODO correct

	SendRoce(data_out, 16 + ICRC_SIZE);
}

void ib_send_rdma_read_req(unsigned char *buffer, int buflen)
{
	// Input
	struct ib_base_transport_header *bth_in;
	struct ib_rdma_extended_transport_header *reth_in;

	// Output
	struct ib_base_transport_header *bth_out;
	struct ib_rdma_extended_transport_header *reth_out;

	// Input
	bth_in = (void *)&buffer[0];

	// Output
	bth_out = (void *)&data_out[0];
	reth_out = (void *)&data_out[sizeof(struct ib_base_transport_header)];

	memset(data_out, 0, 28 + ICRC_SIZE);

	// printf("ib_send_ack : opcode %x", 11);
	bth_out->opcode = IBV_OPCODE_RC_RDMA_READ_REQUEST;
	bth_out->se__m__padcnt__tver = 0;
	bth_out->pkey = ntohs(0xFFFF);
	bth_out->dest_qp = local_qpn << 8;
	bth_out->ack__req = 0x80;
	bth_out->ack__psn = htonl(starting_psn << 8);
	printf("psn %x, %d\n", starting_psn, starting_psn);
	starting_psn++;

	reth_out->virtual_address = htobe64(virtual_addr);
	reth_out->remote_key = htobe32(remote_key);
	reth_out->dma_length = htobe32(len);

	SendRoce(data_out, 28 + ICRC_SIZE);
}

void ib_rc_rdma_read_response_only(unsigned char *buffer, int buflen)
{
	struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr));

	unsigned char *data = (unsigned char *)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct ib_base_transport_header) + sizeof(struct ib_ack_extended_transport_header));
	unsigned int length = ntohs(udp->len) - sizeof(struct udphdr) - sizeof(struct ib_base_transport_header) - sizeof(struct ib_ack_extended_transport_header) - sizeof(struct ib_ack_extended_transport_header);

	fprintf(log_txt, "\n*************************Infiniband packet*******************");
	fprintf(log_txt, "\n rdma read response only\n");
	fprintf(log_txt, "\t|-Lenght                   : %d\n", length);
	fprintf(log_txt, "*****************************************************************\n\n\n");

	payload(data, length, "ib_rc_rdma_read_response_only");
	printf("copy ping buffer %d\n", length);
	memcpy(ping_buffer, data, length);
	ping_size = length;
}

void udp_header(unsigned char *buffer, int buflen)
{
	fprintf(log_txt, "\n*************************UDP Packet******************************");
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
	if (ntohs(udp->dest) == RDMA_PORT)
	{
		// IcrcCheck();
		uint8_t Opcode = ib_header(buffer, buflen);
		LastOpcode = Opcode;

		printf("udp_with_opcode %d\n", LastOpcode);

		switch (Opcode)
		{
		case IBV_OPCODE_UC_SEND_ONLY:
			printf("IBV_OPCODE_UC_SEND_ONLY\n");
			// ib_extended_transport_header(buffer, buflen);
			// ib_mad_header(buffer, buflen);
			// break;
		case IBV_OPCODE_UD_SEND_ONLY:
			printf("IBV_OPCODE_UD_SEND_ONLY\n");
			ib_extended_transport_header(buffer, buflen);
			ib_mad_header(buffer, buflen);
			break;

		case IBV_OPCODE_RC_SEND_ONLY:
			printf("IBV_OPCODE_RC_SEND_ONLY\n");
			ib_rc_send_only_rx(buffer, buflen);
			ib_send_ack(&buffer[42], buflen);
			break;

		case IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY:
			printf("IBV_OPCODE_RD_RDMA_READ_RESPONSE_ONLY\n");
			// ib_rc_rdma_read_response_only(&buffer[42], buflen);
			// rdma_send = 1;
			break;

		case IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY:
			printf("IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY\n");
			ib_rc_rdma_read_response_only(buffer, buflen);
			rdma_send = 1;
			break;

		case IBV_OPCODE_RDMA_READ_REQUEST:
			printf("IBV_OPCODE_RDMA_READ_REQUEST\n");
			// ib_send_rdma_read_response(&buffer[42], buflen);
			break;

		case IBV_OPCODE_RDMA_WRITE_ONLY:
			printf("IBV_OPCODE_RDMA_WRITE_ONLY\n");
			ib_send_rdma_write_response(&buffer[42], buflen);
			break;

		default:
			// printf("\nOpcode = %d\n", Opcode);
			break;
		}
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
		break;

	case 17:
		++udp;
		if (ntohs(ud->dest) == RDMA_PORT)
		{
			// Only process IB packets
			udp_header(buffer, buflen);
		}
		break;

	default:
		++other;
	}
#ifdef DEBUG
	printf("TCP: %d  UDP: %d  Other: %d  : IB %d  ICMP : %d Toatl: %d  \r", tcp, udp, other, ib, icmp, total);
#endif
}

int SendRoce(unsigned char *buffer, int buflen)
{
	return SendRaw(buffer, buflen);
}

int raw_socket()
{
	int sock_r, saddr_len, buflen;
	int message_nr = 0;
	int buffer_size = 65536;

	state = IDLE;

	unsigned char *buffer = (unsigned char *)malloc(buffer_size);
	memset(buffer, 0, buffer_size);

	sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_r < 0)
	{
		printf("error in socket\n");
		return -1;
	}

	struct in_addr own_ip_addr = GetIPAddres(INTF);
	printf("Listining on interface %x\n", own_ip_addr.s_addr);

	while (1)
	{
		saddr_len = sizeof saddr;

		memset(buffer, 0, buffer_size);
		buflen = recvfrom(sock_r, buffer, buffer_size, 0, &saddr, (socklen_t *)&saddr_len);
		message_nr++;

		if (buflen < 0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		fflush(log_txt);

		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

		// Skip message with eq source and destination address
		if (ip->saddr == ip->daddr)
		{
			continue;
		}

		// Filter messages inject by means of the udp_server (echo messages)
		if (ip->daddr != own_ip_addr.s_addr)
		{
			continue;
		}

		// Process incomming data
		data_process(buffer, buflen);

		// Always disconnect when this is requested
		if (ib_dconn_req)
		{
			ib_disconnect_rep(&buffer[42], data_out);
			SendRoce(data_out, 280);
			return 0;
		}
#ifdef DEBUG
		printf("State %d, Lastopcode %d\n", state, LastOpcode);
#endif
		switch (state)
		{
		case IDLE:
			// printf("State = IDLE\n");
			if (ib_conn_req == 1)
			{
				ib_conn_req = 0;
				printf("Connect Request\n");

				// Create and send reply message
				ib_send_rep(&buffer[42], data_out);
				SendRoce(data_out, 280);
			}

			if (ready_to_use == 1)
			{
				ready_to_use = 0;
				state = CONNECTED;
				printf("State = CONNECTED\n");
			}

			break;
		case CONNECTED:
			if (LastOpcode == IBV_OPCODE_RC_SEND_ONLY)
			{
				printf("Start rdma read process\n");
				sleep(DELAY);
				ib_send_rdma_read_req(&buffer[42], buflen);
				state = RDMA_READ_ADV;
			}
			break;
		case RDMA_READ_ADV:
			if (LastOpcode == IBV_OPCODE_RC_RDMA_READ_RESPONSE_ONLY)
			{
				state = RDMA_READ_COMPLETE;
				printf("rdma read finished, ib_send_only \n");
				ib_send_only(&buffer[42], buflen, 0, 0, 0);
			}
			break;
		case RDMA_READ_COMPLETE:
			if (LastOpcode == IBV_OPCODE_RC_ACKNOWLEDGE)
			{
				printf("State = RDMA_READ_COMPLETE\n");
				sleep(DELAY);
				state = RDMA_WRITE_ADV;
			}
			break;
		case RDMA_WRITE_ADV:
			if (LastOpcode == IBV_OPCODE_RC_SEND_ONLY)
			{
				printf("RDMA Write %d\n", ping_size);
				sleep(DELAY);
				ib_rdma_write_only(ping_buffer, ping_size, remote_key, virtual_addr, len);
				state = RDMA_WRITE_COMPLETE;
			}
			break;
		case RDMA_WRITE_COMPLETE:
			if (LastOpcode == IBV_OPCODE_RC_ACKNOWLEDGE)
			{
				printf("RDMA Write done\n");
				sleep(DELAY);
				ib_send_only(&buffer[42], buflen, 0, 0, 0);
				state = CONNECTED;
			}
			break;
		default:
			break;
		}
		LastOpcode = 0;
	}
}

int DummySocket(int PortNr)
{
	int sock_fd, saddr_len, buflen;
	struct sockaddr_in servaddr, cliaddr;

	unsigned char *buffer = (unsigned char *)malloc(65536);
	memset(buffer, 0, 65536);

	printf("starting .... \n");

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0)
	{
		printf("error in socket\n");
		return -1;
	}
	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	// Filling server information 
	servaddr.sin_family = AF_INET; // IPv4 
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PortNr);

	// Bind the socket with the server address 
	if (bind(sock_fd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	int len, n;
	len = sizeof(cliaddr); // len is value/result 

	// while (1)
	// {
	// 	n = recvfrom(sock_fd, (char *)buffer, MAXLINE,
	// 				 MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
	// // sendto(sock_fd, (const char *)hello, strlen(hello), MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);
}

void usage()
{
	printf("Usage:\n");
	printf("udp_server: [-n device]\n");
	exit(1);
}

// Driver code
int main(int argc, char **argv)
{
	int ret, option;

	strcpy(INTF, "lo");

	while ((option = getopt(argc, argv, "n:a:p:")) != -1)
	{
		switch (option)
		{
		case 'n':
			strcpy(INTF, optarg);
			break;
		default:
			usage();
			break;
		}
	}

	printf("\nUsing network if %s\n", INTF);

	initCrc();

	log_txt = fopen("log.txt", "w");
	if (!log_txt)
	{
		printf("unable to open log.txt\n");
		return -1;
	}

	DummySocket(RDMA_PORT); // Prevent ICMP messages
	raw_socket();

	// fclose(log_txt);

	return 0;
}
