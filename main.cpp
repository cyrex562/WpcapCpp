#define _WINSOCKAPI_

#include <cstdint>
#include <cstdio>
#include <csignal>
#include <iostream>
#include <vector>
#include <windows.h>
#include "defines.h"
#include "utils.h"
#include "pcap.h"

HMODULE hLib;
std::vector<struct PacketInfo> packetTable;
//struct PacketRingBuffer pkt_ring_buf = { 0 };

void signalHandler(int sigNum);
Result InitFuncPtrs();
void Prolog();
void initSigHandlers();

/*
 * Main entry function.
 */
int main() {
    // register the signal SIGINT and signal handler
    initSigHandlers();

//    result = ResetRingBuf(&pkt_ring_buf);
//    if (result != ResSuccess) {
//        LogError("%s: failed to initialize packet ring buf\n", __func__);
//    }

    auto result = InitFuncPtrs();
    if (result != ResSuccess) {
        LogError("%s: Failed to initialize function pointers\n", __func__);
        return ResError;
    }
    
    char *iface_name = NULL;
    result = SelectNetworkInterface(&iface_name);
    if (result != ResSuccess) {
        LogError("%s: Failed to process network interfaces\n", __func__);
    }

    char err_buf[PCAP_ERR_BUF_SZ] = { 0 };
    auto pcap_handle = pcapOpen(iface_name,
                          65535,
                          1,
                          1000,
                          NULL,
                          err_buf);
    if (pcap_handle == NULL) {
        LogError("pcapOpen failed: %s\n", err_buf);
        Prolog();
        return ResError;
    }

    /*
     * Grab a packet from the source. Make a copy of the packet.
     */
    while (true) {
        PCAPPacketHeader* packet_header = NULL;
        const uint8_t* pkt_data = NULL;
        auto pcap_next_result = pcapNextEx(pcap_handle,
                                    &packet_header,
                                    &pkt_data);
        if (pcap_next_result == 0) {
            LogWarning("Timeout ocurred\n");
        }
        else if (pcap_next_result == -1) {
            LogError("Error occurred\n");
            result = ResError;
            break;
        }
        else if (pcap_next_result == -2) {
            LogWarning("EOF occurred\n");
            break;
        }
        else if (pcap_next_result == 1) {
            PacketInfo curr_packet = { 0 };
            memcpy(curr_packet.data, pkt_data, packet_header->caplen);
            curr_packet.packet_length = packet_header->len;
            curr_packet.time_stamp = packet_header->ts;
            curr_packet.labels[curr_packet.label_ptr++] = PLPCAP;

            // push the packet into the packet table
            packetTable.push_back(curr_packet);
            auto index = packetTable.size() - 1;
            LogDebug("%s: packet table size: %zu\n", __func__, packetTable.size());

            // push the packet onto the ringBuffer
//            auto ring_buf_result = PushRingBufEle(&pkt_ring_buf, &curr_packet);
//            if (ring_buf_result != ResSuccess) {
//                LogError("%s: Failed to push packet onto ring buffer\n", __func__);
//            }

            //result = ProcessPacket(pktData, pktHdr);
            result = ProcessPacket(packetTable, index);
            if (result != ResSuccess) {
                break;
            }
        }
        else {
            printf("invalid result: %u\n", result);
            result = ResError;
            break;
        }
    }

    Prolog();

    return result;
}




void signalHandler(int sigNum) {
    printf("interrupt signal %i received\n", sigNum);
    // TODO: perform cleanup
    exit(sigNum);
}

Result InitFuncPtrs() {
    // TODO: initialize pcap function pointers based on OS
    Log(LLDebug, "Loading Windows PCAP Library\n");
    hLib = LoadLibrary("wpcap.dll");
    if (hLib == NULL) {
        Log(LLError, "Failed to load library wpcap.dll\n");
        return ResError;
    }

    Log(LLDebug, "Getting function addresses for PCAP function pointers\n");
    pcapFindAllDevs = (PPCAPFindAllDevs)GetProcAddress(hLib, "pcap_findalldevs");
    if (pcapFindAllDevs == NULL) {
        Log(LLError, "Failed to get proc addr for pcap_findalldevs\n");
        Prolog();
        return ResError;
    }

    pcapFreeAllDevs = (PFreeAllDevs)GetProcAddress(hLib, "pcap_freealldevs");
    if (pcapFreeAllDevs == NULL) {
        Log(LLError, "Failed to get proc addr for pcap_freealldevs\n");
        Prolog();
        return ResError;
    }

    pcapOpen = (PPCAPOpen)GetProcAddress(hLib, "pcap_open");
    if (pcapOpen == NULL) {
        Log(LLError, "Failed to get proc addr for pcap_open_live\n");
        Prolog();
        return ResError;
    }

    pcapNextEx = (PPCAPNextEx)GetProcAddress(hLib, "pcap_next_ex");
    if (pcapNextEx == NULL) {
        Log(LLError, "Failed to get proc addr for pcap_next_ex\n");
        Prolog();
        return ResError;
    }

    return ResSuccess;
}

void Prolog() {
    if (hLib != NULL) {
        FreeLibrary(hLib);
    }
}

void initSigHandlers() {
    signal(SIGINT, signalHandler);
    signal(SIGABRT, signalHandler);
    signal(SIGFPE, signalHandler);
    signal(SIGILL, signalHandler);
    signal(SIGSEGV, signalHandler);
    signal(SIGTERM, signalHandler);
}