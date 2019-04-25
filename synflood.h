#ifndef SYNFLOOD_H
#define SYNFLOOD_H

#include <sys/socket.h>     // for socket
#include <sys/types.h>      // for socket
#include <netinet/in.h>     // for sockaddr_in
#include <netinet/tcp.h>    // for tcp
#include <netinet/ip.h>     // for ip
#include <arpa/inet.h>      // for inet_
#include <net/if.h>         // for ifreq
#include <memory.h>         // for memset
#include <unistd.h>         // for usleep
#include <string>

class SynFlood
{
public:
    explicit SynFlood();
    virtual ~SynFlood();

    /*SynFlood初始化*/
    int init(std::string ip_addr, int port);

    /*SynFlood攻击*/
    int attack(int flood_times);
protected:
    /*初始化rawSocket*/
    int initRawSocket();

    /*初始化ip数据报*/
    int initIpData();
private:
    /*addrInfo*/
    std::string ip_addr;
    int port;

    /*rawSocket*/
    struct sockaddr_in addr;    //地址结构体信息
    int socket_fd;              //socket
    unsigned char ip_datagram[sizeof(struct ip) + sizeof(struct tcphdr)];       //ip数据报
    unsigned int ip_datagram_len = sizeof(struct ip) + sizeof(struct tcphdr);   //ip数据报长度
    struct ip *ip_header;       //ip首部指针
    struct tcphdr *tcp_header;  //tcp首部指针

};

#endif // SYNFLOOD_H
