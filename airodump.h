#pragma once
#include <string>
#include <map>
#include <pcap.h>

// 802.11 / Radiotap 구조체
#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((packed));
#pragma pack(pop)

#pragma pack(push, 1)
struct IEEE80211Header {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seqCtrl;
    // 필요시 addr4, QoS Control 등 추가
};
#pragma pack(pop)

// AP 정보 구조체
struct WirelessAPInfo {
    std::string bssid;
    std::string essid;
    int         pwr;       // dBm
    int         beaconCount;
    int         dataCount;
    std::string enc;
};

// 전역 MAP (BSSID -> AP 정보)
extern std::map<std::string, WirelessAPInfo> g_apMap;

// 함수 프로토타입

// Radiotap에서 RSSI 값 추출
int parseRadiotapRSSI(const u_char* packet, uint32_t caplen);

// SSID, ENC 파싱
std::string parseSSID(const u_char* dot11, int dot11Len);
std::string parseEnc(const u_char* dot11, int dot11Len);

// MAC 주소를 문자열로 변경경
std::string macToStr(const uint8_t* mac);

// 패킷 처리 핸들러
void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

// AP 리스트 출력
void printAPList();
