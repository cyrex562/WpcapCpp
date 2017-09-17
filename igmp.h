#pragma once
#include <cstdint>
#include <vector>
#include "defines.h"

/**/
enum IGMPType {
    createGrpReq = 1,
    createGrpReply = 2,
    joinGrpReq = 3,
    joinGrpReply = 4,
    leaveGrpReq = 5,
    leaveGrpReply = 6,
    confirmGrpReq = 7,
    confirmGrpReply = 8,
    groupMembershipQuery = 0x11,
    v1MembershipReport = 0x12,
    DVMRP = 0x13,
    PIMv1 = 0x14,
    CiscoTrace = 0x15,
    IGMPv2MembershipReport = 0x16,
    IGMPv2LeaveGroup =0x17,
    McastTracerouteResp = 0x1e,
    McastTraceroute = 0x1f,
    IGMPv3MembershipReport = 0x22,
    MRDMcastRtrAdvert = 0x30,
    MRDMCastRtrSolicit = 0x31,
    MRDMcastRtrTerm = 0x32
};

enum IGMPReqCode {
    reqPublic = 0,
    reqPrivate = 1
};

enum IGMPRepCode {
    reqGranted = 0,
    reqDeniedNoResc = 1,
    reqDeniedInvalidCode = 2,
    reqDeniedInvalidGrpAddr = 3,
    reqDeniedInvalidKey = 4
    // if the value is greater than 5 it indicates a request pending with a retry timeout.
};

#pragma pack(push, 1)
struct IGMPv0Header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    /* all zero in confirm group request; all other request contains a value to distinguish the request for the host; in replies contains the same value as the corresponding request. */
    uint32_t identifier;
    /* all zeros in create group request; all other requests: contains a host group address; create group reply: newly allocated host group addr or zero if denied; all other replies: contains the same host group address as the corresponding request. */
    uint32_t groupAddress;
    /*
    * create group req: all zero
    * other requests: contains access key assigned to the host group
    * create group reply: non-zero 64-bit num or zero if denied;
    * other replies: same access key as the corresponding request.
    */
    uint64_t accessKey;
};
#pragma pack(pop)

struct IGMPv1Header {
    uint8_t versionType;
    uint8_t unused;
    uint16_t igmpChecksum;
    uint32_t groupAddress;
};

#pragma pack(push, 1)
struct IGMPv2Header {
    uint8_t type;
    uint8_t maxRespTime;
    uint16_t igmpChecksum;
    uint32_t groupAddress;
};
#pragma pack(pop)

void ParseIGMPFrame(std::vector<PacketInfo> packet_table, size_t index);