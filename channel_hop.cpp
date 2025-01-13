// channel_hop.cpp
#include "channel_hop.h"
#include <thread>
#include <chrono>
#include <string>
#include <cstdlib>

// 간단한 채널 호핑 (1,6,11)을 2초 간격으로
void channelHopping(const std::string &iface) {
    int channels[] = {1, 6, 11};
    size_t idx = 0;
    while (true) {
        std::string cmd = "iwconfig " + iface + " channel " + std::to_string(channels[idx]);
        system(cmd.c_str());
        idx = (idx + 1) % (sizeof(channels) / sizeof(channels[0]));
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}
