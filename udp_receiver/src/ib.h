

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
	uint32_t ack__req			: 8;
	uint32_t ack__psn			: 24;
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
