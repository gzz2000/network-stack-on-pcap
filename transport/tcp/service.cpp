#include "ip/ip.hpp"
#include "tcp_internal.hpp"

static bool is_started;

void startTCPService() {
    if(is_started) return;
    is_started = true;
    setIPPacketReceiveCallback(ipCallbackTCP);
    startIPService(scanAllDevices("veth"));
}
