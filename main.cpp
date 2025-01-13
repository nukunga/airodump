// main.cpp
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <pcap.h>
#include "airodump.h"
#include "channel_hop.h"

// 메인 함수
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "syntax : airodump <interface>\n";
        std::cerr << "sample : airodump mon0\n";
        return -1;
    }
    std::string dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1 /*promisc*/, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live(" << dev << ") fail - " << errbuf << "\n";
        return -1;
    }

    // Radiotap 모드인지 체크
    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        std::cerr << "[-] Interface " << dev << " is not in Radiotap mode\n";
        pcap_close(handle);
        return -1;
    }

    // 채널 호핑 쓰레드 (옵션)
    std::thread hopper(channelHopping, dev);
    hopper.detach();

    std::cout << "[*] Start capturing on " << dev << " ...\n";

    auto lastPrintTime = std::chrono::steady_clock::now();
    constexpr int PRINT_INTERVAL = 5;

    while (true) {
        struct pcap_pkthdr* pkthdr;
        const u_char* packet;
        int res = pcap_next_ex(handle, &pkthdr, &packet);
        if (res == 0) {
            // 타임아웃
            auto now = std::chrono::steady_clock::now();
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - lastPrintTime).count();
            if (diff >= PRINT_INTERVAL) {
                system("clear");
                printAPList();
                lastPrintTime = now;
            }
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cerr << "pcap_next_ex error: " << pcap_geterr(handle) << "\n";
            break;
        }

        // 정상 패킷 처리
        packetHandler(nullptr, pkthdr, packet);

        // 주기적 출력
        auto now = std::chrono::steady_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - lastPrintTime).count();
        if (diff >= PRINT_INTERVAL) {
            system("clear");
            printAPList();
            lastPrintTime = now;
        }
    }

    pcap_close(handle);
    return 0;
}
