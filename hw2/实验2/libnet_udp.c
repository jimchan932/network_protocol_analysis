#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
#include <libnet.h> 
#include <time.h>
#include <math.h>

#define LAMBDA 10
#define ON_OFF_ON_TIME 1
#define ON_OFF_OFF_TIME 1

int main(int argc, char *argv[]) 

{ 

    char send_msg[1000] = ""; 

    char err_buf[100] = ""; 

    libnet_t *lib_net = NULL; 

    int lens = 0; 

    libnet_ptag_t lib_t = 0; 

    unsigned char src_mac[6] = {0x94,0xe6,0xf7,0x0a,0xb2,0x61};

//发送者网卡地址00:0c:29:97:c7:c1 

    unsigned char dst_mac[6] = {0xcc,0x66,0x0a,0xe3,0xcd,0xbf};

//接收者网卡地址74-27-EA-B5-FF-D8 

    char *src_ip_str = "192.168.13.227"; //源主机IP地址 

    char *dst_ip_str = "192.168.13.124"; //目的主机IP地址 

    unsigned long src_ip,dst_ip = 0; 

 

    lens = sprintf(send_msg, "%s", "this is for the udp test"); 

 

    lib_net = libnet_init(LIBNET_LINK_ADV, "wlp0s20f3", err_buf);    //初始化 

    if(NULL == lib_net) 
    { 

        perror("libnet_init"); 

        exit(-1); 

    } 

 

    src_ip = libnet_name2addr4(lib_net,src_ip_str,LIBNET_RESOLVE); 

//将字符串类型的ip转换为顺序网络字节流 

    dst_ip = libnet_name2addr4(lib_net,dst_ip_str,LIBNET_RESOLVE); 

 

    lib_t=libnet_build_udp(  //构造udp数据包
8080, 8080, 8+lens, 0, send_msg, lens, lib_net, 0); 

    lib_t = libnet_build_ipv4(  //构造ip数据包 

20+8+lens,0,500,0,10,17, 0, src_ip,dst_ip,NULL,0,lib_net, 0); 

 

    lib_t = libnet_build_ethernet(  //构造以太网数据包 

     (u_int8_t*)dst_mac,(u_int8_t *)src_mac,0x800,NULL,0,lib_net,0); 

    int res = 0; 

    // send packet with Poissan and On/Off models
    srand(time(NULL));
    double on_time = ON_OFF_ON_TIME;
    double off_time = ON_OFF_OFF_TIME;
    while(1)
    {
	double r = (double)rand() / RAND_MAX;
	if(r < on_time / (on_time + off_time))
	{
	    // Turn on
	    double poissan_interval = -log((double)rand()/ RAND_MAX) / LAMBDA;
	    usleep(poissan_interval*1000000);

	    libnet_write(lib_net);    //发送数据包 
	}
	else
	{
	    usleep(off_time * 1000000);
	}
    }
    libnet_destroy(lib_net);    //销毁资源 

    printf("----ok-----\n");
    
    return 0; 
} 
