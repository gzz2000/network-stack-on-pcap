#include "compose.hpp"
#include <thread>

void startComposedCapturing(std::vector<int> interfaces) {
    std::vector<std::thread> threads;
    for(int id: interfaces) {
        threads.emplace_back(startCapturing, id);
    }
    for(std::thread &t: threads) {
        t.join();
    }
    fprintf(stderr, "startComposedCapturing reached the end. No capture running.\n");
}
