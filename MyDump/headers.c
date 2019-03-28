#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"

typedef struct eth_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}eth_address;

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;


/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* MAC header*/
typedef struct eth_header
{
	eth_address daddr;
	eth_address saddr;
	u_short type;
}eth_header;


typedef struct arp_header
{
	u_short hardtype;			//硬件类型字段
	u_short prototype;			//协议类型字段
	u_char htlen;				//硬件地址的长度,以字节为单位.对于以太网上IP地址的ARP请求或应答来说,它们的值为6
	u_char ptlen;				//协议地址的长度,以字节为单位.对于以太网上IP地址的ARP请求或应答来说,它们的值为4
	u_short op;					//操作字段
	eth_address arp_esa;		//发送端MAC地址
	ip_address arp_isa;			//发送端IP地址
	eth_address arp_eda;		//目的端MAC地址
	ip_address arp_ida;			//目的端IP地址
}arp_header;


typedef struct icmp_header
{
	u_char type;				//ICMP报文类型
	u_char code;				//代码
	u_short checksum;			//校验和
	u_short identifier;			//标识符
	u_short sequence_number;	//序列号
}icmp_header;

/* TCP header */
typedef struct tcp_header
{
	u_short	sport;					//源端口
	u_short dport;					//目的端口
	u_long  sequence_number;		//序号（4字节ntohl）  
	u_long  acknowlegement_number;	//确认号
	u_short hlen_bl_flags;			//数据偏移+保留+控制位
	u_short window_size;			//窗口（发送方自己的接收窗口）
	u_short checksum;				//检验和（首部+数据）
	u_short urg;					//紧急指针
	u_long  option;					//可选+填充
}tcp_header;

typedef struct dns_packet //报文head+data
{
    u_short id;		//每一个占2个字节，共12个字节
    u_short flags;	//标志第一个为0代表查询报文
    u_short ques;	
    u_short answer;	
    u_short author;	
    u_short addition;
    u_char dns_data;	//查询问题部分
}dns_packet;