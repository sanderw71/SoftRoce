#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>

#include <net/if.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/udp.h>  //Provides declarations for tcp header
#include <netinet/ip.h>   //Provides declarations for ip header

#include <linux/if_packet.h>

#include "crc32.h"


int total_len = 0, send_len;
unsigned char *sendbuff;
struct ifreq ifreq_c, ifreq_i, ifreq_ip; /// for each ioctl keep diffrent ifreq structure otherwise error may come in sending(sendto )

#define RDMA_PORT 4791
#define SPORT 55410
extern char INTF[];
extern char src_mac[6];

extern struct sockaddr_in source;

struct in_addr GetIPAddres(char *Ifname)
{

    int n;
    struct ifreq ifr;

    n = socket(AF_INET, SOCK_DGRAM, 0);

    // Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;

    // Copy the interface name in the ifreq structure
    strcpy(ifr.ifr_name, Ifname);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);

    // display result
    printf("IP Address is %s - %s\n", Ifname, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
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

void get_eth_index(int sock_raw)
{
    memset(&ifreq_i, 0, sizeof(ifreq_i));
    strncpy(ifreq_i.ifr_name, INTF, IFNAMSIZ - 1);

    if ((ioctl(sock_raw, SIOCGIFINDEX, &ifreq_i)) < 0)
        printf("error in index ioctl reading");
}

void get_mac(int sock_raw)
{
    memset(&ifreq_c, 0, sizeof(ifreq_c));
    strncpy(ifreq_c.ifr_name, INTF, IFNAMSIZ - 1);

    if ((ioctl(sock_raw, SIOCGIFHWADDR, &ifreq_c)) < 0)
        printf("error in SIOCGIFHWADDR ioctl reading");

    // printf("Mac= %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]), (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]));
    // printf("ethernet packaging start ... \n");

    struct ethhdr *eth = (struct ethhdr *)(sendbuff);

    // Set source MAC
    eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
    eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
    eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
    eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
    eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
    eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

    // Set destination MAC
    memcpy(eth->h_dest, src_mac, sizeof(eth->h_dest));

    eth->h_proto = htons(ETH_P_IP); // 0x800

    total_len += sizeof(struct ethhdr);
}

void get_udp(unsigned char *buffer, int buflen)
{
    struct udphdr *uh = (struct udphdr *)(sendbuff + sizeof(struct iphdr) + sizeof(struct ethhdr));

    uh->source = htons(SPORT);
    uh->dest = htons(RDMA_PORT);
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
    iph->daddr = source.sin_addr.s_addr; //   inet_addr("destination_ip"); // put destination IP address
    total_len += sizeof(struct iphdr);
    get_udp(buffer, buflen);

    iph->tot_len = htons(total_len - sizeof(struct ethhdr));
    iph->check = htons(checksum((unsigned short *)(sendbuff + sizeof(struct ethhdr)), (sizeof(struct iphdr) / 2)));
}

int SendRaw(unsigned char *buffer, int buflen)
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

    // Set dest MAC adddres
    memcpy(sadr_ll.sll_addr, src_mac, sizeof(src_mac)); // Size ?

    // InserCrc
    InsertIcrc(sendbuff, total_len);

    printf("sending...\n");
    send_len = sendto(sock_raw, sendbuff, total_len, 0, (const struct sockaddr *)&sadr_ll, sizeof(struct sockaddr_ll));
    if (send_len < 0)
    {
        printf("error in sending....sendlen=%d....errno=%d\n", send_len, errno);
        return -1;
    }
}
