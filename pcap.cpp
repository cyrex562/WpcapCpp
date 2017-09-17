#include "pcap.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include "defines.h"
#include "utils.h"
#include "ethernet.h"

//void initPcap() {
//    PPCAPFindAllDevs pcapFindAllDevs = NULL;
//    PFreeAllDevs pcapFreeAllDevs = NULL;
//    PPCAPOpen pcapOpen =  NULL;
//    PPCAPNextEx pcapNextEx = NULL;
//}

extern PPCAPFindAllDevs pcapFindAllDevs = NULL;
extern PFreeAllDevs pcapFreeAllDevs = NULL;
extern PPCAPOpen pcapOpen = NULL;
extern PPCAPNextEx pcapNextEx = NULL;

/*
* Process the network interfaces.
*/
Result SelectNetworkInterface(char **ifaceName) {
    auto i = 0;
    auto iface_cnt = 0;
    pcap_if_t* interfaces[64] = { 0 };
    pcap_if_t* allDevs;
    uint16_t choice = 0;
    
    char errBuf[PCAP_ERR_BUF_SZ] = { 0 };
    LogDebug("getting list of devices\n");
    auto result = pcapFindAllDevs(&allDevs, errBuf);
    if (result == -1) {
        LogError("error calling pcap_findalldevs: %s\n", errBuf);
        return ResError;
    }

    for (pcap_if_t* dev = allDevs; dev; dev = dev->next) {
        LogDebug("%d: name: \"%s\"\n", ++i, dev->name);
        iface_cnt++;
        LogDebug("\tdesc: ");
        if (dev->description) {
            LogDebug("\"%s\"\n", dev->description);
        }
        else {
            LogDebug("none\n");
        }
        interfaces[i] = dev;
        if (dev->addresses) {
            LogDebug("\taddresses: \n");
            for (pcap_addr* addr = dev->addresses; addr; addr = addr->next) {
                LogDebug("\t\taddress: \n");
                if (addr->addr) {
                    LogDebug("\t\t\tsrc_addr: ");
                    if (addr->addr->sa_family == AF_INET) {
                        LogDebug("%hhu.%hhu.%hhu.%hhu\n",
                            addr->addr->sa_data[2],
                            addr->addr->sa_data[3],
                            addr->addr->sa_data[1],
                            addr->addr->sa_data[0]);
                    } else {
                        LogWarning("unhandled AF type: %s\n", 
                            SockAddrFamToStr(addr->addr->sa_family));
                    }
                }
                else {
                    LogDebug("\t\t\tsrc_addr: none\n");
                }
                
                if (addr->dstaddr) {
                    LogDebug("\t\t\tdst_addr: ");
                    if (addr->dstaddr->sa_family == AF_INET) {
                        LogDebug("%hhu.%hhu.%hhu.%hhu\n",
                            addr->dstaddr->sa_data[2],
                            addr->dstaddr->sa_data[3],
                            addr->dstaddr->sa_data[1],
                            addr->dstaddr->sa_data[0]);
                    } else {
                        LogWarning("unhandled AF type: %s\n", 
                            SockAddrFamToStr(addr->dstaddr->sa_family));
                    }
                }
                else {
                    LogDebug("\t\t\tdst_addr: none \n");
                }
                
                if (addr->broadaddr) {
                    LogDebug("\t\t\tbcast: ");
                    if (addr->broadaddr->sa_family == AF_INET) {
                        LogDebug("%hhu.%hhu.%hhu.%hhu\n",
                            addr->broadaddr->sa_data[2],
                            addr->broadaddr->sa_data[3],
                            addr->broadaddr->sa_data[1],
                            addr->broadaddr->sa_data[0]);
                    } else {
                        LogWarning("unhandled AF type: %s\n", 
                            SockAddrFamToStr(addr->broadaddr->sa_family));
                    }
                }
                else {
                    LogDebug("\t\t\tbcast: none ");
                }
                
                if (addr->netmask) {
                    LogDebug("\t\t\tmask: ");
                    if (addr->netmask->sa_family == AF_INET) {
                        LogDebug("%hhu.%hhu.%hhu.%hhu\n",
                            addr->netmask->sa_data[2],
                            addr->netmask->sa_data[3],
                            addr->netmask->sa_data[1],
                            addr->netmask->sa_data[0]);
                    } else {
                        LogWarning("unhandled AF type: %s\n", 
                            SockAddrFamToStr(addr->netmask->sa_family));
                    }
                }
                else {
                    LogDebug("mask: none\n");
                }
            }
        }
        else {
            Log(LLDebug, "addresses: none\n");
        }
    }

    printf("select an interface to capture traffic from: ");
    scanf("%hu", &choice);
    printf("\n");

    static char _ifaceName[0xffff] = { 0 };
    strcat(_ifaceName, "rpcap://");
    strcat(_ifaceName, interfaces[choice]->name);
    *ifaceName = _ifaceName;

    pcapFreeAllDevs(allDevs);

    return ResSuccess;
}

//Result ProcessPacket(const uint8_t* pktData,
//                     struct PCAPPacketHeader* pktHdr) {
Result ProcessPacket(std::vector<PacketInfo> packet_table, size_t index) {
    Log(LLDebug, "\n\n** PACKET **\n");
    
    /* pulling a packet from the ringbuffer currently requires an additional copy operation because the ringbuffer pops the packet when retrieving it. We should figure out a way to 'access' the packet rather than copying, but still allow packets to be overrun. */
//    RingBufElement rbe = { 0 };
//    auto result = getRingBufEle(pktRingBuf, &rbe);
//    if (result != ResSuccess) {
//        LogError()
//    }
//    PacketInfo* ringBufPkt = getRingBufEle(pktRingBuf);
//
//    PacketInfo pktInfo = { 0 };
//    memcpy(&pktInfo, ringBufPkt, sizeof(PacketInfo));
//    auto pkt_len = packet_table[index].packet_length;
//    PacketLabel* labels = &packet_table[index].labels[0];
//    size_t packet_label_ptr = packet_table[index].label_ptr;
//    uint8_t* pkt_data = &packet_table[index].data[0];
//    auto ptr = 0;

    ParseEthernetFrame(packet_table, index);
//    ParseEthernetFrame(pkt_data, ptr, pkt_len);

    return ResSuccess;
}