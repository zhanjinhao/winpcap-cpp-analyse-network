#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include "headers.c"
#define DNSPORT 53



//输出基本信息
void myPrintBaseInfo(const struct pcap_pkthdr *header)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("\n\n\n\n监听到Mac帧的时间：%s   MAC帧长度:%d Byte(s)\n", timestr, header->len * 4);  /* 以四字节为单位 */
}

//输出硬件地址
void myPrintEthAddress(eth_address eth)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X", 
		eth.byte1,
		eth.byte2,
		eth.byte3,
		eth.byte4,
		eth.byte5,
		eth.byte6
	);
}

//输出IP地址
void myPrintIPAddress(ip_address ia)
{
	printf("%d.%d.%d.%d", 
		ia.byte1,
		ia.byte2,
		ia.byte3,
		ia.byte4
	);
}

//输出网络层协议类型
void myPrintNetType(u_short type)
{
	printf("网络层协议： ");
	if(type==0x0800)
		printf("IP协议");
	else if(type==0x0806)
		printf("ARP协议");
	else if(type==0x8035)
		printf("RARP协议");
	else
		printf("接收到非本程序能处理的网络层协议类型！");
	printf("\n");
}

/*
	分析Mac帧：
		输出：
			网络层协议类型：源MAC -> 目的MAC
		
		返回：
			网络层协议类型
*/
u_short handleMac(eth_header *eth)
{
	u_short type=ntohs(eth->type);	
	printf("Mac地址： ");
	myPrintEthAddress(eth->saddr);
	printf("->");
	myPrintEthAddress(eth->daddr);
	printf("\n\n");
	return type;
}

void handleARPAndRARP(arp_header *ah)
{
	u_short arp_ht;			//硬件地址的类型.它的值为1即表示以太网地址
	u_short arp_pt;			//要映射的协议地址类型.它的值为0x0800，即表示IP地址
	u_short arp_op;			//四种操作类型,它们是ARP请求(值为1)、ARP应答(值为2)、RARP请求(值为3)和RARP应答(值为4)
	arp_ht=ntohs(ah->hardtype);				//硬件地址的类型.它的值为1即表示以太网地址
	arp_pt=ntohs(ah->prototype);			//要映射的协议地址类型.它的值为0x0800，即表示IP地址
	arp_op=ntohs(ah->op);
	
	printf("硬件地址类型为：%d\t\t\t",arp_ht);
	printf("协议地址类型为：0x%04X\n",arp_pt);
	printf("硬件地址长度为：%d\t\t\t",ah->htlen);
	printf("协议地址长度为：%d\n",ah->ptlen);
	if (arp_op == 1){
		printf("操作类型为：ARP请求报文。\n本机Mac地址：");
		myPrintEthAddress(ah->arp_esa);
		printf("\t正在请求");
		myPrintIPAddress(ah->arp_ida);
		printf("的Mac地址\n");
	}
	
	if (arp_op == 2){
		printf("操作类型为：ARP应答报文。\n应答方的Mac地址：");
		myPrintEthAddress(ah->arp_eda);
		printf("\t应答方的IP地址");
		myPrintIPAddress(ah->arp_ida);
		printf("\n");
	}

	if (arp_op == 3)
		printf("操作类型为：RARP请求报文\n");
	if (arp_op == 4)
		printf("操作类型为：RARP应答报文\n");
}

int all_ip_len = 20;

u_short handleIP(ip_header *ih)
{
	u_int ip_ver;		//版本
	u_int ip_len;		//首部长度
	u_short ip_tlen;    //总长度
	u_short ip_ident;	//标识
	u_short ip_flag_fo; //标志和片偏移
	u_int ip_flag;		//标志（3位，值为2还有分片且允许分片,1不能分片,0没有分片且允许分片）
	u_int ip_fo;		//片偏移
	u_short ip_type;	//协议
	u_short ip_crc;		//首部检验和
	u_long ip_op_pad;	//可选项

	/* retireve the position of the ip header *///检索IP首部的位置
	ip_ver = (ih->ver_ihl >> 4);			//版本
	ip_len = (ih->ver_ihl & 0xf) * 4;		//首部长度，与运算，可以只取ip头部的版本长度字段的后4位
	ip_tlen=ntohs(ih->tlen);				//总长度
	ip_ident=ntohs(ih->identification);		//标识
	ip_flag_fo = ntohs(ih->flags_fo);		//2字节存放，会有字节序问题
	ip_flag = (ip_flag_fo >> 13);			//标志
	ip_fo = (ip_flag_fo & 0x1fff);			//片偏移
	ip_type = ih->proto;					//上层协议类型
	ip_crc = ntohs(ih->crc);				//首部校验和

	/*打印IP数据报首部*/
	printf("版本：%d\t\t\t",ip_ver);
	printf("首部长度：%d\n",ip_len);
	printf("区分服务：%d\t\t", ih->tos);
	printf("总长度：%d\n", ip_tlen);
	printf("标识：%d\t\t", ip_ident);
	if (ip_flag == 2)
		printf("标志：DF=1（不能分片），MF=0（没有后续分片）\n");
	if (ip_flag == 1)
		printf("标志：DF=0（允许分片），MF=1（还有后续分片）\n");
	if (ip_flag == 0)
		printf("标志：DF=0（允许分片），MF=0（没有后续分片）\n");
	printf("片偏移：%d\t\t",ip_fo*8);//片偏移以8字节为单位
	printf("生存时间：%d\n",ih->ttl);
	printf("协议：%d\t\t\t",ih->proto);
	printf("首部校验和：%d\n",ip_crc);

	printf("IP地址：  ");

	myPrintIPAddress(ih->saddr);
	printf(" -> ");
	myPrintIPAddress(ih->daddr);
	printf("\n");
	if (ip_len == 20)//IP首部长度>20时才有
		printf("首部长度为20，IP报文首部没有可选字段。\n");
	else{
		ip_op_pad = ntohl(ih->op_pad);
		printf("可选自段内容为：%u\n", ip_op_pad);
	}
	all_ip_len = ip_len;

	return ip_type;
}

void handleICMP(icmp_header *ich)
{
	u_short icmp_checksum;		//校验和
	u_short icmp_ident;			//标识符
	u_short icmp_seqnum;		//序列号

	icmp_checksum = ntohs(ich->checksum);				//校验和
	icmp_ident = ntohs(ich->identifier);				//标识符
	icmp_seqnum = ntohs(ich->sequence_number);

	printf("\n运输层协议：  ICMP协议\n");

	/*打印ICMP报文首部*/
	if (ich->type == 0)
		printf("ICMP类型：回显应答\n");
	else if (ich->type == 8)
		printf("ICMP类型：回显请求\n");
	else
		printf("ICMP类型：其他\n");
	printf("代码：%d\t\t",ich->code);
	printf("校验和：%d\n",icmp_checksum);
	printf("标识符：%d\t\t",icmp_ident);
	printf("序列号：%d\n",icmp_seqnum);
}

u_int udp_len;

bool handleUDP(udp_header *uh)
{
	u_short sport, dport;//端口
	u_short uh_len;		 //长度
	u_short uh_crc;		 //校验和

	sport = ntohs( uh->sport );//源端口
	dport = ntohs( uh->dport );//目的端口
	uh_len = ntohs(uh->len);	//长度
	uh_crc = ntohs(uh->crc);	//校验和
	printf("\n运输层协议：  UDP协议\n");
	printf("端口号：%d -> %d\n", sport, dport);
	printf("长度：%d\t\t", uh_len);
	printf("校验和：%d\n", uh_crc);

	udp_len = uh_len;
	
	if(sport == DNSPORT || dport == DNSPORT)
		return true;
	return false;
}

void handleTCP(tcp_header *th)
{
	u_short	tcp_sport;			//源端口
	u_short tcp_dport;			//目的端口
	u_long  tcp_seqnum;			//序号（4字节ntohl）  
	u_long  tcp_acknum;			//确认号
	u_short tcp_hlen_bl_flags;	//数据偏移+保留+控制位
	u_short  tcp_hlen;
	u_short  tcp_bl;		
	u_short  tcp_flags_urg;		//紧急1有效 
	u_short  tcp_flags_ack;		//确认=1时，确认号有效
	u_short  tcp_flags_psh;		//推送1有效，可以不用填满缓存就发报
	u_short  tcp_flags_rst;		//复位1有效，重新建立连接
	u_short  tcp_flags_syn;		//同步syn=1,ack=0时，表明这是一个连接请求报文；syn=1,ack=1,接受连接请求
	u_short  tcp_flags_fin;		//释放连接=1时，表示数据报
	u_short tcp_window_size;	//窗口（发送方自己的接收窗口）
	u_short tcp_checksum;		//检验和（首部+数据）
	u_short tcp_urg;			//紧急指针
	u_long tcp_option;	

	tcp_sport=ntohs(th->sport);					//源端口
	tcp_dport=ntohs(th->dport);					//目的端口
	tcp_seqnum=ntohl(th->sequence_number);		//序号（4字节ntohl）  
	tcp_acknum=ntohl(th->acknowlegement_number);//确认号
	tcp_hlen_bl_flags=ntohs(th->hlen_bl_flags);	//数据偏移4+保留6+控制位6
	tcp_hlen=(tcp_hlen_bl_flags >> 12)*4;		//以4字节为单位
	tcp_bl=(tcp_hlen_bl_flags & 0x0fc0);		//保留
	tcp_flags_urg=(tcp_hlen_bl_flags & 0x0020);	//紧急1有效                                                    ----- 
	tcp_flags_ack=(tcp_hlen_bl_flags & 0x0010);	//确认=1时，确认号有效
	tcp_flags_psh=(tcp_hlen_bl_flags & 0x0008);	//推送1有效，可以不用填满缓存就发报
	tcp_flags_rst=(tcp_hlen_bl_flags & 0x0004);	//复位1有效，重新建立连接
	tcp_flags_syn=(tcp_hlen_bl_flags & 0x0002);	//同步syn=1,ack=0时，表明这是一个连接请求报文；syn=1,ack=1,接受连接请求
	tcp_flags_fin=(tcp_hlen_bl_flags & 0x0001);	//释放连接=1时，表示数据报
	tcp_window_size=ntohs(th->window_size);		//窗口（发送方自己的接收窗口）
	tcp_checksum=ntohs(th->checksum);			//检验和（首部+数据）
	tcp_urg=ntohs(th->urg);	

	printf("\n运输层协议：  TCP协议\n");

	/*打印TCP数据报首部*/
	printf("端口号：%d -> %d\n",tcp_sport,tcp_dport);
	printf("序号：%u\t",tcp_seqnum);
	printf("确认号：%u\n",tcp_acknum);
	printf("数据偏移：%d\t\t",tcp_hlen);//首部长度
//	printf("保留：%d\n",tcp_bl);
	/*控制字段,标志位*/
	if (tcp_flags_urg == 1)
		printf("标志：URG\n");
	if (tcp_flags_ack == 1)
		printf("标志：ACK\n");
	if (tcp_flags_psh == 1)
		printf("标志：PSH\n");
	if (tcp_flags_rst == 1)
		printf("标志：RST\n");
	if (tcp_flags_syn == 1)
		printf("标志：SYN\n");
	if (tcp_flags_fin == 1)
		printf("标志：FIN\n");
	printf("窗口：%d\t\t",tcp_window_size);
	printf("检验和：%d\n",tcp_checksum);
	printf("紧急指针：%d\t\t",tcp_urg);//URG=1时才有用，窗口大小为0也能发送
	if(tcp_hlen == 20)//数据偏移(TCP首部长度)>20时才有
		printf("首部长度为20字节，没有填充字段。\n");
	else {
		tcp_option = ntohl(th->option);
		printf("填充字段:%u\n", tcp_option);
	}
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)   //param 无用
{

	eth_header *eth;
	u_short macType;

	myPrintBaseInfo(header);

	eth=(eth_header *) (pkt_data);

	//过滤以太网头部
	pkt_data += 14;

	//HandleMac
	macType=handleMac(eth);
	myPrintNetType(macType);

	// 处理ARP 和 RARP
	if(macType==0x0806 || macType==0x8035)
	{
		arp_header *ap;
		ap = (arp_header *)(pkt_data);
		handleARPAndRARP(ap);
	}

	// 处理IP
	if(macType==0x0800)
	{
		u_short ip_type;
		ip_header *ih;
		ih = (ip_header *) (pkt_data);	
		ip_type = handleIP(ih);

		if (ip_type == 1) {
			icmp_header *ich;
			ich = (icmp_header *)((u_char*)ih + all_ip_len);
			handleICMP(ich);
		}else if(ip_type == 17){
			udp_header *uh;
			uh = (udp_header *) ((u_char*)ih + all_ip_len);
			
			
			if(handleUDP(uh))
			{
				/*
				struct dns_packet *pdns;
				pdns = (struct dns_packet *)(pkt_data + all_ip_len + udp_len); // sport+dport+length+checksum,DNS头指针
 
				u_char *query=&(pdns->dns_data);//定位到查询部分头部
				printf("QueryDomain=");
				u_char domainname[100]={0};
 
				u_int i=0;
				//query++;//把点去了

				while(*query)
				{

					printf("%d", *query);

					if(*query < 0x10)//48以后出现数字和英文字母
						printf(".");
					else
						printf("%c", *query);
					query++;
					i++;
				}

				printf("\n"); */
				
			}
		}else if(ip_type == 6){
			tcp_header *th;
			th=(tcp_header *) ((u_char*)ih + all_ip_len);
			handleTCP(th);
		}
	}
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int handType;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char *packet_filter;
	packet_filter = new char[100];
	int i = 0;
	
	
	
	printf("分析IP数据报输入：\t\t\t1\n");
	printf("分析ARP数据报输入：\t\t\t2\n");
	printf("分析TCP数据报输入：\t\t\t3\n");
	printf("分析UDP数据报输入：\t\t\t4\n");
	printf("分析ICMP数据报输入：\t\t\t5\n");
	printf("分析MAC、IP、ARP、TCP、UDP、IMCP输入\t6\n");

	printf("输入您想分析协议类型：");
	scanf("%d", &handType);


	if(handType == 1)
		packet_filter = "ip";
	else if(handType == 2)
		packet_filter = "arp";
	else if(handType == 3)
		packet_filter = "ip and tcp";
	else if(handType == 4)
		packet_filter = "ip and udp";
	else if(handType == 5)
		packet_filter = "ip and icmp";
	else if(handType == 6)
		packet_filter = "";
	else{
		printf("InputError : check the number you input! exit(1)");
		exit(1); 
	}
	
	struct bpf_program fcode;
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	return 0;
}
