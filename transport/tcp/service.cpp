#include "ip/ip.hpp"
#include "tcp_internal.hpp"
#include "socket_wrapper.hpp"
#include <chrono>

static bool is_started;

void startTCPService() {
    if(is_started) return;
    is_started = true;
#ifdef RUNTIME_INTERPOSITION
    init_reals();
#endif
    setIPPacketReceiveCallback(ipCallbackTCP);
    startIPService(scanAllDevices("veth"));
    // Need to sleep to wait for routing table setup
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(3s);
}
