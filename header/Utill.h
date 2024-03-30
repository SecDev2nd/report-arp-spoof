#pragma once

#include <iostream>
#include <arpa/inet.h>
#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <iostream>
#include <cstdlib>
#include <string>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "AttackerInfo.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage();

void print_info(struct libnet_ipv4_hdr *header,
                u_int8_t *m,
                u_int8_t *m2);

Mac getSenderMac(pcap_t *handle,
                 Mac myMAc,
                 Ip myIP,
                 Ip senderIp);

Mac getTargetMac(pcap_t *handle,
                 Mac myMac,
                 Ip myIp,
                 Ip targetIp);

EthArpPacket Sender_Infection(const char *interfaceName,
                              Mac my_mac,
                              Mac SenderMac,
                              Ip sip,
                              Ip tip);

EthArpPacket Target_Infection(char *interfaceName, Mac my_mac, Mac SenderMac, Ip sip, Ip tip);

Mac getTargetMac(pcap_t *handle,
                 Mac myMac,
                 Ip myIP,
                 Ip TargetIp);

EthArpPacket Make_packet(char *interfaceName,
                         Mac eth_dmac,
                         Mac eth_smac,
                         Mac arp_smac,
                         Ip arp_sip,
                         Mac arp_tmac,
                         Ip arp_tip);