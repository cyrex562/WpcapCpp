#include <cstdint>
#include <cstdio>

#include "igmp.h"
#include "utils.h"


char* igmpTypeToStr(uint8_t igmpType) {
    static char igmpTypeStr[64] = { 0 };
    switch (igmpType) {
    case createGrpReq:
        sprintf(igmpTypeStr, "%s", "Create Group Request");
        break;
    case createGrpReply:
        sprintf(igmpTypeStr, "%s", "Create Group Reply");
        break;
    case joinGrpReq:
        sprintf(igmpTypeStr, "%s", "Join Group Request");
        break;
    case joinGrpReply:
        sprintf(igmpTypeStr, "%s", "Join Group Reply");
        break;
    case leaveGrpReq:
        sprintf(igmpTypeStr, "%s", "Leave Group Request");
        break;
    case leaveGrpReply:
        sprintf(igmpTypeStr, "%s", "Leave Group Reply");
        break;
    case confirmGrpReq:
        sprintf(igmpTypeStr, "%s", "Confirm Group Request");
        break;
    case confirmGrpReply:
        sprintf(igmpTypeStr, "%s", "Confirm Group Reply");
        break;
    case groupMembershipQuery:
        sprintf(igmpTypeStr, "%s", "Group Membership Query");
        break;
    case v1MembershipReport:
        sprintf(igmpTypeStr, "%s", "V1 Membership Report");
        break;
    case DVMRP:
        sprintf(igmpTypeStr, "%s", "DVMRP");
        break;
    case PIMv1:
        sprintf(igmpTypeStr, "%s", "PIMv1");
        break;
    case CiscoTrace:
        sprintf(igmpTypeStr, "%s", "Cisco Trace");
        break;
    case IGMPv2MembershipReport:
        sprintf(igmpTypeStr, "%s", "IGMPv2 Membership Report");
        break;
    case IGMPv2LeaveGroup:
        sprintf(igmpTypeStr, "%s", "IGMPv2 Leave Group");
        break;
    case McastTracerouteResp:
        sprintf(igmpTypeStr, "%s", "Multicast Traceroute Response");
        break;
    case McastTraceroute:
        sprintf(igmpTypeStr, "%s", "Multicast Traceroute");
        break;
    case IGMPv3MembershipReport:
        sprintf(igmpTypeStr, "%s", "IGMPv3 Membership Report");
        break;
    case MRDMcastRtrAdvert:
        sprintf(igmpTypeStr, "%s", "MRD Multicast Router Advertisement");
        break;
    case MRDMCastRtrSolicit:
        sprintf(igmpTypeStr, "%s", "MRD Mulicast Router Solicitation");
        break;
    case MRDMcastRtrTerm:
        sprintf(igmpTypeStr, "%s", "MRD Multicast Router Termination");
        break;
    default:
        sprintf(igmpTypeStr, "(unk %hhu)", igmpType);

    }
    return igmpTypeStr;
}

char* igmpCodeToStr(uint8_t igmpCode, bool request) {
    static char igmpCodeStr[64] = { 0 };
    if (request) {
        switch (igmpCode) {
        case reqPublic:
            sprintf(igmpCodeStr, "%s", "Request Public");
            break;
        case reqPrivate:
            sprintf(igmpCodeStr, "%s", "Request Private");
            break;
        default:
            sprintf(igmpCodeStr, "unk %hhu", igmpCode);
        }
    } else {
            switch(igmpCode) {
            case reqGranted:
                sprintf(igmpCodeStr, "%s", "Request Granted");
                break;
            case reqDeniedNoResc:
                sprintf(igmpCodeStr, "%s", "Request Denied: No Resources");
                break;
            case reqDeniedInvalidCode:
                sprintf(igmpCodeStr, "%s", "Request Denied: Invalid Code String");
                break;
            case reqDeniedInvalidGrpAddr:
                sprintf(igmpCodeStr, "%s", "Request Denied: Invalid Group Address");
                break;
            case reqDeniedInvalidKey:
                sprintf(igmpCodeStr, "%s", "Request Denied: Invalid Key");
                break;
            default:
                sprintf(igmpCodeStr, "unk %hhu", igmpCode);
            }

        }

    return igmpCodeStr;
}

/*
* Process an IGMP Frame
*/
void processIGMPFrame(const uint8_t* pktData, uint32_t ptr) {
    log(LLDebug, "IGMP frame\n");
    auto type = (uint8_t)pktData[ptr];
    log(LLDebug, "\ttype: %s (%hhu)\n", igmpTypeToStr(type), type);
    if (type <= 8) {
        //igmpv0
        auto igmpHdr = (struct IGMPv0Header*)&pktData[ptr];
        auto isRequest = true;
        if (igmpHdr->type == 2 || igmpHdr->type == 4 || igmpHdr->type == 6 || igmpHdr->type == 8) {
            isRequest = false;
        }
        
        log(LLDebug, "\tcode: %s (%hhu)\n", igmpCodeToStr(igmpHdr->code, isRequest), igmpHdr->code);
        log(LLDebug, "\tidentifier: %08x\n", _ntohl(igmpHdr->identifier));
        
        log(LLDebug, "\taccessKey: %016llx\n", igmpHdr->accessKey);
    } else if (type <= 0x13) {
        //igmpv1
        auto igmpHdr = (struct IGMPv1Header*)&pktData[ptr];
        log(LLDebug, "\tgroupAddress: %08x\n", _ntohl(igmpHdr->groupAddress));
    } else if (type <= 0x32) {
        //igmpv2/v3
        auto igmpHdr = (struct IGMPv2Header*)&pktData[ptr];
        log(LLDebug, "\tmax Response Time: %hhu\n", igmpHdr->maxRespTime);
        log(LLDebug, "\tgroupAddress: %08x\n", _ntohl(igmpHdr->groupAddress));
    } else {
        log(LLError, "unsupported igmp type: %hhu\n", type);
    }
    return;
}
