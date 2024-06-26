#pragma once

#include <iostream>
#include <arpa/inet.h>
#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <iostream>
#include <cstdlib>
#include <string>

#include "ethhdr.h"
#include "arphdr.h"

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

Mac getSenderMac(
                 Mac myMAc,
                 Ip myIP,
                 Ip senderIp,
                 char* interfcae_name);

Mac getTargetMac(
                 Mac myMac,
                 Ip myIp,
                 Ip targetIp,
                 char* interfcae_name);

// Mac getTargetMac(pcap_t *handle,
//                  Mac myMac,
//                  Ip myIP,
//                  Ip TargetIp);

EthArpPacket Sender_Infection(char *interfaceName,
                              Mac my_mac,
                              Mac SenderMac,
                              Ip sip,
                              Ip tip);

EthArpPacket Target_Infection(char *interfaceName, Mac my_mac, Mac SenderMac, Ip sip, Ip tip);



EthArpPacket Make_packet(char *interfaceName,
                         Mac eth_dmac,
                         Mac eth_smac,
                         Mac arp_smac,
                         Ip arp_sip,
                         Mac arp_tmac,
                         Ip arp_tip);

bool checkRecoverPacket(EthArpPacket &packet, Ip SenderIP, Ip TargetIp, Mac TargetMac, Mac SenderMac);
Mac getMacAddress(char *interfaceName);
Ip getAttackerIp(char *interfaceName);
