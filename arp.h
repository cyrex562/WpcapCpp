#pragma once
#include "defines.h"
#include <cstdint>
#include <vector>

enum hType {
    hTypeReserved = 0,
    hTypeEthernet = 1,
    hTypeIEEE802 = 6,
    hTypeDLCI = 15,
    hTypeATM = 19,
    hTypeFiberChan = 18,
    hTypeSerial = 20,
    hTypeMILSTD188_220 = 22,
    hTypeIEEE1394_1995 = 24,
    hTypeTwinAx = 26,
    hTypeEUI64 = 27,
    hTypeIPARPISO7816_3 = 29,
    hTypeIPSEC = 31,
    hTypeInfiniband = 32,
    hTypeCAIP25 = 33,
    hTypeSLIP = 256,
    hTypeCSLIP = 257,
    hTypeSLIP6 = 258,
    hTypeCSLIP6 = 259,
    hTypeCAN = 280,
    hTypePPP = 512,
    hTypeCiscoHDLC = 513,
    hTypeRawHDLC = 518,
    hTypeIPIPTun = 768,
    hTypeIPIPTun6 = 769,
    hTypeLoopback = 772,
    hTypeFDDI = 774,
    hTypeSIT = 776,
    hTypeGRE = 778,
    hTypePIMREG = 779,
    hTypeFCPP = 784, // PtP Fibre Chan
    hTypeFCAL = 785, // FC Arbitrated Loop
    hTypeFCPL = 786, // FC Public Loop
    hTypeFCFabric = 787, // FC Fabric
    hTypeIEEE802TR = 800, // TR
    hTypeIEEE80211 = 801,
    hTypeIEEE80211Prism = 802,
    hTypeIEEE80211RadioTap = 803,
    hTypeIEEE802154 = 804, // 802.15.4
    hTypeIEEE802154Monitor = 805, // 802.15.4 net monitor
    hTypeIPv6GRE = 823, // GRE over IPv6
    hTypeNetlink = 824,
    hTtpe6LoWPAN = 825,
};

enum pType {
    pTypeIP = 0x0800
};

enum ARPOpCode {
    arpOpReserved = 0,
    arpOpRequest = 1,
    arpOpReply = 2,
    arpOpReqRev = 3,
    arpOpRepRev = 4,
    arpOpARPNAK = 10
};

#pragma pack(push, 1)
struct ARPHeader {
    uint16_t hType;
    uint16_t pType;
    uint8_t hLen;
    uint8_t pLen;
    uint16_t operation;
    EthernetAddress sndHWAddr;
    IPV4Address sndProtoAddr;
    EthernetAddress tgtHWAddr;
    IPV4Address tgtProtoAddr;
}; // 28 bytes
#pragma pack(pop)

void ParseARPFrame(std::vector<PacketInfo> packet_table, size_t index);