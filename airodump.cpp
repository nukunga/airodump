// airodump.cpp
#include "airodump.h"
#include <iostream>
#include <iomanip>
#include <cstdio>
#include <cstdlib>
#include <cstring>

std::map<std::string, WirelessAPInfo> g_apMap;

// Radiotap에서 RSSI 값 파싱
int parseRadiotapRSSI(const u_char* packet, uint32_t caplen) {
    if (caplen < sizeof(RadiotapHeader)) return -999;
    const RadiotapHeader* rh = reinterpret_cast<const RadiotapHeader*>(packet);
    if (rh->it_len > caplen) return -999;

    // 여기서는 "DBM_ANTSIGNAL이 14바이트 정도에 있다"라고 가정한 간단 버전.
    // 실제로는 present mask, alignment 등을 정교하게 파싱해야 함.
    int radiotapLen = rh->it_len;
    int rssiVal = -999;
    if (radiotapLen >= 14) {
        rssiVal = *(int8_t*)(packet + 13); // 예: 14바이트 지점 - 1
    }
    return rssiVal;
}

// SSID 파싱 (Beacon/Probe Response 등)
std::string parseSSID(const u_char* dot11, int dot11Len) {
    const int mgmtFixedLen = 12;
    if (dot11Len < mgmtFixedLen) return "";
    int offset = mgmtFixedLen;
    while (offset + 2 <= dot11Len) {
        uint8_t tagNum = dot11[offset];
        uint8_t tagLen = dot11[offset+1];
        if (offset + 2 + tagLen > dot11Len) break;

        if (tagNum == 0) { // SSID
            if (tagLen == 0) return "<hidden>";
            return std::string(reinterpret_cast<const char*>(dot11 + offset + 2), tagLen);
        }
        offset += (2 + tagLen);
    }
    return "";
}

// 암호화 파싱(RSN, WPA)
std::string parseEnc(const u_char* dot11, int dot11Len) {
    const int mgmtFixedLen = 12;
    if (dot11Len < mgmtFixedLen) return "OPN";
    int offset = mgmtFixedLen;
    bool wpa = false, wpa2 = false;
    while (offset + 2 <= dot11Len) {
        uint8_t tagNum = dot11[offset];
        uint8_t tagLen = dot11[offset+1];
        if (offset + 2 + tagLen > dot11Len) break;

        const u_char* body = dot11 + offset + 2;
        if (tagNum == 0x30) { // RSN
            wpa2 = true;
        } else if (tagNum == 0xdd && tagLen >= 4) {
            if (body[0] == 0x00 && body[1] == 0x50 && body[2] == 0xF2 && body[3] == 0x01) {
                wpa = true;
            }
        }
        offset += (2 + tagLen);
    }
    if (wpa2) return "WPA2";
    if (wpa)  return "WPA";
    return "OPN";
}

// MAC -> 문자열
std::string macToStr(const uint8_t* mac) {
    char buf[20];
    std::sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// 패킷 핸들러(Beacon, Data 프레임 등 파싱)
void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    int rssi = parseRadiotapRSSI(packet, header->caplen);
    const RadiotapHeader* rh = reinterpret_cast<const RadiotapHeader*>(packet);
    int radiotapLen = rh->it_len;
    if (radiotapLen <= 0 || radiotapLen > (int)header->caplen) return;

    const u_char* dot11 = packet + radiotapLen;
    int dot11Len = header->caplen - radiotapLen;
    if (dot11Len < (int)sizeof(IEEE80211Header)) return;

    const IEEE80211Header* wh = reinterpret_cast<const IEEE80211Header*>(dot11);
    uint16_t fc = wh->frameControl;
    uint8_t type    = (fc & 0x000c) >> 2; // 0:Mgmt,1:Ctrl,2:Data
    uint8_t subtype = (fc & 0x00f0) >> 4; // 0~15

    // Beacon (Management, subtype=8)
    if (type == 0 && subtype == 8) {
        std::string bssid = macToStr(wh->addr3);
        if (g_apMap.find(bssid) == g_apMap.end()) {
            WirelessAPInfo info;
            info.bssid       = bssid;
            info.essid       = "";
            info.pwr         = -999;
            info.beaconCount = 0;
            info.dataCount   = 0;
            info.enc         = "OPN";
            g_apMap[bssid]   = info;
        }

        g_apMap[bssid].pwr = rssi;
        g_apMap[bssid].beaconCount++;

        std::string essid = parseSSID(dot11 + sizeof(IEEE80211Header), dot11Len - sizeof(IEEE80211Header));
        if (!essid.empty()) g_apMap[bssid].essid = essid;

        std::string enc = parseEnc(dot11 + sizeof(IEEE80211Header), dot11Len - sizeof(IEEE80211Header));
        g_apMap[bssid].enc = enc;
    }
    // Data frame (type=2)
    else if (type == 2) {
        // addr2를 BSSID로 가정
        std::string bssid = macToStr(wh->addr2);
        if (g_apMap.find(bssid) != g_apMap.end()) {
            g_apMap[bssid].dataCount++;
        }
    }
}

// AP 리스트 출력
void printAPList() {
    std::cout << " BSSID              PWR   Beacons  #Data   ENC   ESSID\n";
    std::cout << " ----------------------------------------------------------\n";
    for (auto &kv : g_apMap) {
        auto &ap = kv.second;
        std::cout << " " << std::setw(17) << std::left << ap.bssid
                  << std::setw(6) << ap.pwr
                  << std::setw(9) << ap.beaconCount
                  << std::setw(7) << ap.dataCount
                  << std::setw(6) << ap.enc
                  << "   " << ap.essid << "\n";
    }
    std::cout << std::endl;
}
