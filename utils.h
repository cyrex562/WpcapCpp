#pragma once

enum LogLevel {
    LLDebug,
    LLInfo,
    LLNotice,
    LLWarning,
    LLError
};

uint32_t _ntohl(uint32_t in32);
uint16_t _ntohs(uint16_t in16);
uint32_t _ntohl(uint32_t in32);
void log(LogLevel level, const char* fmt, ...);
void printBytes(const uint8_t* bytes, size_t count);
char *addrFamToStr(int addrFam);