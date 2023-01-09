/************************************************************
*    File: MultiMask_match_sampling.c
*
*    Experiment 4: Use libpcap to capture and sample packets based on MultiMask matching
*    Match the IP identification information with the mask
*    print the captured packets
*	 in each computer network hierarchy protocol, 
*	 and save them to a pcap file.
*
*    To compile:
*    >gcc MultiMask_match_sampling.c -lpcap -lm -o MultiMask_match_sampling
*
*    To run:
*    >sudo ./MultiMask_match_sampling
*
*    Enter the number of the device you want to sniff: 
*    >2
*
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
#include<math.h>  //Provides the pow() function
#include<unistd.h>


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int multmask_matching(const u_char * Buffer);
void tobin(u_int16_t a,char* str);
int Sampling_ratio_decomposition(float ratio);
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;	
pcap_t *handle;


// set the sampling ratio
float ratio;
// set the sampling parameter
int parameter = 0;
// set mask[]
int mask[16] = {0};
// set the number of mask
int number = 0;


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

    //Ask user the sampling ratio
    printf("Enter the ratio of the sampling: ");
	scanf("%f" , &ratio);

    //get the parameter
    parameter = Sampling_ratio_decomposition(ratio);
    printf("\n");
    printf("parameter:%d\n",parameter);
    printf("number:%d\n",number);

    // print device
	printf("\nOpening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 0 , -1 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf); 
		exit(1);
	}
	printf("Done\n");

    // open pcap file and wait the packet update  
    out_pcap = pcap_dump_open(handle,"/home/jiapengli/sampling/MultiMask_match_sampling.pcap");   
   
	// Put the device in sniff loop
	pcap_loop(handle , 500 , process_packet , (u_char*)out_pcap);
    printf("Total : %d\n",total);

	// refresh buffer
	pcap_dump_flush(out_pcap); 

	// close resource
    pcap_dump_close(out_pcap);   
	return 0;	
}

/*********************************************************************************************************/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	if(multmask_matching(buffer)) //Sampling interval
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

int multmask_matching(const u_char * Buffer)
{
	// Get the ID of IPheader 
	unsigned short iphdrlen;
    u_int16_t ip_id;
	char str[16] = {0};	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    int flag = 0;
    ip_id= ntohs(iph->id);

    // Convert IP_identification to binary
    tobin(ip_id,str);
    int len = strlen(str);
    
    // Get the first non-zero occurrence of the Identifies , NO.L
    int L = 17-len;

    // Multimask sampling algorithm
    for(int i =0;i<number-1;i++)
    {
        if(mask[i] == L)
        {
            flag = 1;
            printf("The L is:%d\n",L);
            return flag;
        }
    }
    return flag;
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

int Sampling_ratio_decomposition(float ratio)
{
    float a =ratio;
    int P = 0;
    printf("mask:");
    for(int i =1;i<17;i++)
    {
        if(a>1.0/(pow(2,i)))
        {
            a = a -(1.0/pow(2,i));
            P = P + pow(2,i);
            //get the mask and its number
            mask[number] = i;
            printf("%d,",i);
            number++;
        }
    }
    return P;
}