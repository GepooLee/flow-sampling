/************************************************************
*    File: Periodic_sampling.c
*    Experiment 1: Use libpcap to capture and sample packets Periodically
*	 print the details of the captured packets 
*	 in each computer network hierarchy protocol, 
*	 and save them to a pcap file.
*
*    To compile:
*    >gcc Periodic_sampling.c -lpcap -o Periodic_sampling
*
*    To run:
*    >sudo ./Periodic_sampling
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

int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
pcap_t *handle;
int timeLen = 1;
int count = 1;
int interval; //Sampling interval

int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed
    pcap_dumper_t* out_pcap;

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

	//Ask user the sampling interval
    printf("Enter the interval of the sampling: ");
	scanf("%d" , &interval);
	
	printf("\nOpening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 0 , -1 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

    // open pcap file and wait the packet update  
    out_pcap = pcap_dump_open(handle,"/home/jiapengli/sampling/Periodic_sampling.pcap");   
   
	// Put the device in sniff loop
	pcap_loop(handle , 99 , process_packet , (u_char*)out_pcap);

	// refresh buffer
	pcap_dump_flush(out_pcap); 

	// close resource
    pcap_dump_close(out_pcap);   
	return 0;	
}

/*********************************************************************************************************/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{

	if(count%interval==0) //Sampling interval
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
	++count;
}

