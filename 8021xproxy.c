#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h> 
#include <pthread.h>  
#include <unistd.h>  
#include <string.h>  
#define DEV_1 "eth0" //lan
#define DEV_2 "eth1" //wan 
#define PC_MAC packet[6]==0xbc && packet[7]==0x5f && packet[8]==0xf4 && packet[9]==0x92 && packet[10]==0xc7 && packet[11]==0x99



void getPacket_1(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  
  int * id = (int *)arg;  
  char errBuf[PCAP_ERRBUF_SIZE];  
  int d;
  for(d=0;d<1000;d++);
  printf("I am from thread1 \n");    
  printf("id: %d\n", ++(*id));  
  printf("Packet length: %d\n", pkthdr->len);  
  printf("Number of bytes: %d\n", pkthdr->caplen);  
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));   
   
  int i;  
 /* for(i=0; i<pkthdr->len; ++i)  
  {  
    printf(" %02x", packet[i]);  
    if( (i + 1) % 16 == 0 )  
    {  
      printf("\n");  
    }  
  }  
  */  
  printf("\n\n");  
 

//*************lan2wan*****************
//if source from pc then packet it to WAN else drop it.
if (PC_MAC)
{
printf("find pc_MAC yes! \n \n");
//sendpacket
static pcap_t * device;
if(device == NULL)
{
pcap_t * device = pcap_open_live(DEV_2, 65535, 1, 0, errBuf);  
pcap_sendpacket(device, packet ,pkthdr->len);
}
else
{ 
//printf("pcap_open_live(): %s\n",errBuf); exit(1); //open error
pcap_sendpacket(device, packet ,pkthdr->len);
} 
//pcap_close(device);  
}
//*****************************
printf("\n\n"); 
}  

void getPacket_2(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  
  int * id = (int *)arg;  
char errBuf[PCAP_ERRBUF_SIZE];  
  printf("I am from thread2 \n");  
  printf("id: %d\n", ++(*id));  
  printf("Packet length: %d\n", pkthdr->len);  
  printf("Number of bytes: %d\n", pkthdr->caplen);  
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));   
    
  int i; 
/*  
  for(i=0; i<pkthdr->len; ++i)  
  {  
    printf(" %02x", packet[i]);  
    if( (i + 1) % 16 == 0 )  
    {  
      printf("\n");  
    }  
  }  
*/
    
  printf("\n\n"); 
//*************wan2lan***************** 
//if source not from pc the packet it to LAN else drop it
if (!(PC_MAC))
{
printf("Not find pc_MAC !  \n \n");
//sendpacket
static pcap_t * device; 
if(device == NULL)
 { 
pcap_t * device = pcap_open_live(DEV_1, 65535, 1, 0, errBuf);  
pcap_sendpacket(device, packet ,pkthdr->len) ;
//pcap_close(device);  
   }
else
 { 
pcap_sendpacket(device, packet ,pkthdr->len) ;
   }
}  
}
  
void *thread_1 ()//监听lan
{
 char errBuf[PCAP_ERRBUF_SIZE];//, * devStr;  
 int id = 0;    
  /* get a device */  
  //devStr = pcap_lookupdev(errBuf);  
  //devStr=DEV_1;
  pcap_t * device = pcap_open_live(DEV_1, 65535, 1, 0, errBuf);  
    
  if(!device)  
  {  
    printf("error: pcap_open_live(): %s\n", errBuf);  
    exit(1);  
  }  
else  
  {  
   printf("success: device: %s\n", DEV_1); 
  } 
    
  /* construct a filter */  
  struct bpf_program filter;  
  pcap_compile(device, &filter, "ether proto 0x888E", 1, 0);  
  pcap_setfilter(device, &filter);  
    
  /* wait loop forever */  
   
  pcap_loop(device, -1, getPacket_1, (u_char*)&id);  //使用回调 调用发包函数
    
  pcap_close(device);  
  
  return 0;  
}

void *thread_2 ()//监听wan
{

    char errBuf[PCAP_ERRBUF_SIZE];//, * devStr;  
 int id = 0;    
  /* get a device */  
  //devStr = pcap_lookupdev(errBuf);  
  //devStr=DEV_2;  
  pcap_t * device = pcap_open_live(DEV_2, 65535, 1, 0, errBuf);  
    
  if(!device)  
  {  
    printf("error: pcap_open_live(): %s\n", errBuf);  
    exit(1);  
  }  
else  
  {  
   printf("success: device: %s\n", DEV_2); 
  }  

  /* construct a filter */  
  struct bpf_program filter;  
  pcap_compile(device, &filter, "ether proto 0x888E", 1, 0);  
  pcap_setfilter(device, &filter);  
    
  /* wait loop forever */  
   
  pcap_loop(device, -1, getPacket_2, (u_char*)&id);  //回调函数
    
  pcap_close(device);  
  
  return 0;  
}


int main()  
{  
   pthread_t th_a, th_b;
   void *retval; 
   pthread_create(&th_a, NULL, thread_1, 0);
   pthread_create(&th_b, NULL, thread_2, 0);
   pthread_join(th_a, &retval);
   pthread_join(th_b, &retval);
   return 0;
}  


