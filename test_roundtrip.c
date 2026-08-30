#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "protocol.h"

int main() {
    uint8_t ek[32]; memset(ek, 0x42, 32);
    uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    uint32_t counter = 100;
    uint64_t session_id = 0xDEADBEEFCAFEBABE;
    uint32_t conn_id = 42;
    int fail = 0;
    
    // Тест 1: короткая строка
    { uint8_t data[]="Hello"; uint8_t out[4096]; size_t ol=4096; gost_packet_t pkt;
      uint32_t exp_pc = counter+2;
      protocol_pack_data(&pkt,session_id,conn_id,data,5,ek,nonce,&counter,0);
      uint32_t pc=0; int r=protocol_unpack_data(&pkt,out,&ol,NULL,ek,nonce,&pc,0);
      if(r!=0||ol!=5||pc!=exp_pc){printf("Test1 FAIL: r=%d ol=%u pc=%u exp=%u\n",r,(int)ol,pc,exp_pc);fail=1;}
      else printf("Test1: OK (pc=%u)\n",pc); }
    // Тест 2: средняя строка
    { uint8_t data[]="Hello, Gost-Proxy!"; uint8_t out[4096]; size_t ol=4096; gost_packet_t pkt;
      uint32_t exp_pc = counter+2;
      protocol_pack_data(&pkt,session_id,conn_id,data,18,ek,nonce,&counter,0);
      uint32_t pc=0; int r=protocol_unpack_data(&pkt,out,&ol,NULL,ek,nonce,&pc,0);
      if(r!=0||ol!=18){printf("Test2 FAIL: r=%d ol=%u pc=%u\n",r,(int)ol,pc);fail=1;}
      else printf("Test2: OK (pc=%u)\n",pc); }
    // Тест 3: большая строка
    { uint8_t data[200]; uint8_t out[4096]; size_t ol=4096; gost_packet_t pkt;
      memset(data,'A',sizeof(data));
      uint32_t exp_pc = counter+2;
      protocol_pack_data(&pkt,session_id,conn_id,data,200,ek,nonce,&counter,0);
      uint32_t pc=0; int r=protocol_unpack_data(&pkt,out,&ol,NULL,ek,nonce,&pc,0);
      if(r!=0||ol!=200||memcmp(out,data,200)!=0){printf("Test3 FAIL\n");fail=1;}
      else printf("Test3: OK (pc=%u)\n",pc); }
    // Тест 4: разные session_id
    { uint8_t data[]="test"; uint8_t out[4096]; size_t ol=4096; gost_packet_t pkt;
      uint32_t exp_pc = counter+2;
      protocol_pack_data(&pkt,0x1111111111111111ULL,conn_id,data,4,ek,nonce,&counter,0);
      uint32_t pc=0; int r=protocol_unpack_data(&pkt,out,&ol,NULL,ek,nonce,&pc,0);
      if(r!=0||ol!=4||memcmp(out,data,4)!=0){printf("Test4 FAIL\n");fail=1;}
      else printf("Test4: OK (pc=%u, sid=0x111..1)\n",pc); }
    // Тест 5: counter check — два пакета подряд
    { uint8_t data1[]="AAA",data2[]="BBB"; uint8_t out[4096]; size_t ol=4096; gost_packet_t pkt1,pkt2;
      counter=200;
      protocol_pack_data(&pkt1,session_id,conn_id,data1,3,ek,nonce,&counter,0);
      protocol_pack_data(&pkt2,session_id,conn_id,data2,3,ek,nonce,&counter,0);
      uint32_t pc1=0,pc2=0;
      int r1=protocol_unpack_data(&pkt1,out,&ol,NULL,ek,nonce,&pc1,0);
      ol=4096;
      int r2=protocol_unpack_data(&pkt2,out,&ol,NULL,ek,nonce,&pc2,0);
      if(r1!=0||r2!=0||pc1!=202||pc2!=204){printf("Test5 FAIL: pc1=%u pc2=%u\n",pc1,pc2);fail=1;}
      else printf("Test5: OK (pc1=%u pc2=%u)\n",pc1,pc2); }
    printf("\n%s\n",fail?"FAIL":"ALL PASSED");
    return fail;
}
