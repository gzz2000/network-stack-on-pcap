#include "tcp_internal.hpp"
#include "link/ethernet/getaddr.hpp"
#include "ip/ip.hpp"
#include <cstring>

std::string debugSegmentSummary(const void *iphdr_0, const void *tcpbuf, int len) {
    const ip_header_t *iphdr = (const ip_header_t *)iphdr_0;
    const tcp_header_t *tcphdr = (const tcp_header_t *)tcpbuf;
    std::string src = ip2str(iphdr->src) + ":" + std::to_string(tcphdr->src_port);
    std::string dest = ip2str(iphdr->dest) + ":" + std::to_string(tcphdr->dst_port);
    std::string flags;
#define TEST_FLAG(name) if(tcphdr->flags & TH_##name) flags += " " #name
    TEST_FLAG(FIN);
    TEST_FLAG(SYN);
    TEST_FLAG(RST);
    TEST_FLAG(PUSH);
    TEST_FLAG(ACK);
    TEST_FLAG(URG);
    TEST_FLAG(ECE);
    TEST_FLAG(CWR);
#undef TEST_FLAG
    return "SEG: " + src + " -> " + dest + flags
        + " seq=" + std::to_string(tcphdr->seq) + " ack=" + std::to_string(tcphdr->ack) + " len=" + std::to_string(len);
}

uint16_t computeTCPChecksum(const void *iphdr_0, const void *tcpbuf, int len /* payload len */) {
    const ip_header_t *iphdr = (const ip_header_t *)iphdr_0;
    const tcp_header_t *tcphdr = (const tcp_header_t *)tcpbuf;
    uint32_t sum = 0;
    // pseudo IP header
    sum += iphdr->src >> 16;
    sum += iphdr->src & 0xFFFF;
    sum += iphdr->dest >> 16;
    sum += iphdr->dest & 0xFFFF;
    sum += iphdr->protocol;
    sum += uint16_t(len + 4 * tcphdr->data_offset);
    // tcp header
    for(int i = 0; i < 2 * tcphdr->data_offset; ++i) {
        sum += ((uint16_t *)tcpbuf)[i];
    }
    sum -= tcphdr->checksum;
    // tcp data
    const uint8_t *data = (uint8_t *)tcpbuf + 4 * tcphdr->data_offset;
    for(int i = 0; i < len; i += 2) {
        if(i + 2 <= len) sum += *(uint16_t *)(data + i);
        else sum += (uint16_t)(data[i]) << 8;
    }
    // one's complement
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

void sendTCPSegment(socket_t src, socket_t dest, uint8_t flags,
                    uint32_t seq, uint32_t ack, const void *buf, uint32_t len) {
    char tcpbuf[20 + len];
    tcp_header_t *tcphdr = (tcp_header_t *)tcpbuf;
    tcphdr->src_port = src.port;
    tcphdr->dst_port = dest.port;
    tcphdr->seq = seq;
    tcphdr->ack = ack;
    tcphdr->data_offset = 5;
    tcphdr->flags = flags;
    tcphdr->window_size = 16384;
    tcphdr->urgent_p = 0;
    memcpy(tcpbuf + 20, buf, len);
    ip_header_t pseudo_iphdr;
    pseudo_iphdr.src = src.ip;
    pseudo_iphdr.dest = dest.ip;
    pseudo_iphdr.protocol = IP_PROTO_TCP;
    tcphdr->checksum = computeTCPChecksum(&pseudo_iphdr, tcpbuf, len);
    int ret = sendIPPacket(src.ip, dest.ip, IP_PROTO_TCP, tcpbuf, 20 + len);
    if(ret < 0) {
        fprintf(stderr, "sendTCPSegment called sendIPPacket, which failed\n");
    }
}

int ipCallbackTCP(const void *buf, int len) {
    const ip_header_t *iphdr = (const ip_header_t *)buf;
    if(iphdr->protocol != IP_PROTO_TCP) {
        fprintf(stderr, "Not TCP packet: IP proto %d\n", iphdr->protocol);
        return 0;
    }
    const tcp_header_t *tcphdr = (const tcp_header_t *)(
        (const char *)buf
        + 4 * (iphdr->ver_ihl & 0xF));
    socket_t src_socket{iphdr->src, tcphdr->src_port};
    socket_t dst_socket{iphdr->dest, tcphdr->dst_port};
    std::scoped_lock lock(pools_mutex);
    if(auto it_b = binds.find(dst_socket); it_b != binds.end()) {
        Connection &conn = init_connection(dst_socket, src_socket, STATUS_LISTEN);
        conn.q_thread.push(recv_segment_lambda(buf, len));
        it_b->second.q_socket.push(src_socket);
    }
    else if(auto it_b = binds.find(socket_t{0u, dst_socket.port}); it_b != binds.end()) {
        // wildcard bind
        Connection &conn = init_connection(dst_socket, src_socket, STATUS_LISTEN);
        conn.q_thread.push(recv_segment_lambda(buf, len));
        it_b->second.q_socket.push(src_socket);
    }
    else if(auto it_c = conns.find(std::make_pair(dst_socket, src_socket));
            it_c != conns.end()) {
        it_c->second.q_thread.push(recv_segment_lambda(buf, len));
    }
    else {
        fprintf(stderr, "TCP segment not corresponding to any socket: %s\n",
                debugSegmentSummary(iphdr, tcphdr,
                                    iphdr->total_length - 4 * (iphdr->ver_ihl & 0xF) - 4 * tcphdr->data_offset).c_str());
    }
    return 0;
}
