/************************************************************
*    File: Mask_match_sampling.c
*
*    Experiment 3: Use libpcap to capture and sample packets based on Mask matching
*    Match the IP identification information with the mask
*    print the captured packets
*	 in each computer network hierarchy protocol, 
*	 and save them to a pcap file.
*
*    To compile:
*    >gcc Mask_match_sampling.c -lpcap -o Mask_match_sampling
*
*    To run:
*    >sudo ./Mask_match_sampling
*
*    Enter the number of the device you want to sniff: 
*    >1
*
***************************************************************/

#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip.h>	//Provides declarations for ip header
#include <unistd.h>


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int ip_character_mask(const u_char * Buffer);
void tobin(u_int16_t a,char* str);

int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
pcap_t *handle;
int m;
char cpre[16] = {0};

int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed
    pcap_dumper_t* out_pcap;

    // m = strlen(cpre);
	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;

	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff: ");
	scanf("%d" , &n);
	devname = devs[n];

	//Ask user the number of the bits used for mask sampling
    printf("Enter the number of the bits used for mask sampling: ");
	scanf("%d" , &m);
	for(int i=0;i<m;i++)
	{
		cpre[i]='1';
	}

	printf("\nOpening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 0 , -1 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf); 
		exit(1);
	}
	printf("Done\n");

    // open pcap file and wait the packet update  
    out_pcap = pcap_dump_open(handle,"/home/jiapengli/sampling/Mask_match_sampling.pcap");   
   
	// Put the device in sniff loop
	pcap_loop(handle , 100 , process_packet , (u_char*)out_pcap);

	// refresh buffer
	pcap_dump_flush(out_pcap); 

	// close resource
    pcap_dump_close(out_pcap);   
	return 0;	
}

/*********************************************************************************************************/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	if(ip_character_mask(buffer)) //Sampling interval
	{
		// Export traffic data to pcap file
		pcap_dump(args, header, buffer);  
	
		//Get the IP Header part of this packet , excluding the ethernet header
		struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
		++total;
		switch (iph->protocol) //Check the Protocol and do accordingly...
		{
			case 1:  //ICMP Protocol
				++icmp;
				break;
		
			case 2:  //IGMP Protocol
				++igmp;
				break;
		
			case 6:  //TCP Protocol
				++tcp;
				break;
		
			case 17: //UDP Protocol
				++udp;
				break;
		
			default: //Some Other Protocol like ARP etc.
				++others;
				break;
		}
		printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);
	}
}

int ip_character_mask(const u_char * Buffer)
{
	unsigned short iphdrlen;
    u_int16_t ip_id;
	char str[16] = {0};	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );

    ip_id= ntohs(iph->id);
    // Convert IP_identification to binary
    tobin(ip_id,str);
    int len = strlen(str);
	// Mask matching
    for(int i =0;i<m;i++)
    {
        if(cpre[m-i-1] != str[len-i-1])
        return 0;
    }
    printf( "   |-Identification    : %d\n",ntohs(iph->id));
    printf("%s\n",str);
    return 1;

}

void tobin(u_int16_t a,char* str)
{
	// p points to the first address of a
	char *p=(char*)&a,c=0,f=0,pos=-1;
	for(int o=0;o<2;++o)
	{
    	for(int i=0;i<8;++i)
    	{ 
      	c=p[1-o]&(1<<(7-i));
      	if(!f&&!(f=c))continue;
      	str[++pos]=c?'1':'0';
    	}
	}
}