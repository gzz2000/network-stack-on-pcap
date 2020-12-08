#include "tcp_internal.hpp"
#include "link/ethernet/getaddr.hpp"
#include "ip/ip.hpp"
#include <arpa/inet.h>
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
    sum += ntohs(iphdr->protocol);
    sum += ntohs(uint16_t(len + 4 * (tcphdr->data_offset >> 4)));
    // tcp header
    for(int i = 0; i < 2 * (tcphdr->data_offset >> 4); ++i) {
        sum += ((uint16_t *)tcpbuf)[i];
    }
    sum -= tcphdr->checksum;
    // tcp data
    const uint8_t *data = (uint8_t *)tcpbuf + 4 * (tcphdr->data_offset >> 4);
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
    tcphdr->src_port = htons(src.port);
    tcphdr->dst_port = htons(dest.port);
    tcphdr->seq = htonl(seq);
    tcphdr->ack = htonl(ack);
    tcphdr->data_offset = 5 << 4;
    tcphdr->flags = flags;
    tcphdr->window_size = htons(16384);
    tcphdr->urgent_p = 0;
    memcpy(tcpbuf + 20, buf, len);
    ip_header_t pseudo_iphdr;
    pseudo_iphdr.src = src.ip;
    pseudo_iphdr.dest = dest.ip;
    pseudo_iphdr.protocol = IP_PROTO_TCP;
    tcphdr->checksum = computeTCPChecksum(&pseudo_iphdr, tcpbuf, len);
    int ret = sendIPPacket(src.ip, dest.ip, IP_PROTO_TCP, tcpbuf, 20 + len);
    if(ret < 0) {
        fprintf(stderr, "[TCP Error] sendTCPSegment called sendIPPacket, which failed\n");
    }
}

int ipCallbackTCP(const void *buf, int len) {
    const ip_header_t *iphdr0 = (const ip_header_t *)buf;
    if(iphdr0->protocol != IP_PROTO_TCP) {
        fprintf(stderr, "[TCP Error] Not TCP packet: IP proto %d\n",
                iphdr0->protocol);
        return 0;
    }
    const tcp_header_t *tcphdr0 = (const tcp_header_t *)(
        (const char *)buf
        + 4 * (iphdr0->ver_ihl & 0xF));
    size_t payload_len = ntohs(iphdr0->total_length) \
        - 4 * (iphdr0->ver_ihl & 0xF) - 4 * (tcphdr0->data_offset >> 4);
    uint16_t correct_checksum = computeTCPChecksum(iphdr0, tcphdr0, payload_len);

    // copy, and reverse byte orders
    std::shared_ptr<uint8_t[]> copy_buf(new uint8_t[len]);
    memcpy(copy_buf.get(), buf, len);
    ip_header_t *iphdr = (ip_header_t *)copy_buf.get();
    tcp_header_t *tcphdr = (tcp_header_t *)(
        (const char *)copy_buf.get() + 4 * (iphdr->ver_ihl & 0xF));
    iphdr->total_length = htons(iphdr->total_length);
    tcphdr->src_port = ntohs(tcphdr->src_port);
    tcphdr->dst_port = ntohs(tcphdr->dst_port);
    tcphdr->seq = ntohl(tcphdr->seq);
    tcphdr->ack = ntohl(tcphdr->ack);
    tcphdr->window_size = ntohs(tcphdr->window_size);

    if(tcphdr->checksum != correct_checksum) {
        fprintf(stderr, "[TCP Error] drop segment: bad tcp checksum. %s\n",
                debugSegmentSummary(iphdr, tcphdr, payload_len).c_str());
        return 0;
    }
    
    socket_t src_socket{iphdr->src, tcphdr->src_port};
    socket_t dst_socket{iphdr->dest, tcphdr->dst_port};

    auto recv_segment_lambda = [copy_buf, iphdr, tcphdr, payload_len]
        (socket_t src, socket_t dest, Connection &conn) {
        tcp_conn_recv_segment(src, dest, conn, iphdr, tcphdr, payload_len);
    };
    
    std::scoped_lock lock(pools_mutex);

    if(auto it_c = conns.find(std::make_pair(dst_socket, src_socket));
            it_c != conns.end()) {
        it_c->second.q_thread.push(recv_segment_lambda);
    }
    else if(tcphdr->flags != TH_SYN) {
        fprintf(stderr, "[TCP Error] only SYN can be sent to bind. %s\n",
                debugSegmentSummary(iphdr, tcphdr, payload_len).c_str());
    }
    else if(auto it_b = binds.find(dst_socket); it_b != binds.end()) {
        if(tcphdr->flags != TH_SYN) {
            fprintf(stderr, "[TCP Error] only SYN can be sent to bind. %s\n",
                    debugSegmentSummary(iphdr, tcphdr, payload_len).c_str());
        }
        Connection &conn = init_connection(dst_socket, src_socket, STATUS_LISTEN);
        conn.q_thread.push(recv_segment_lambda);
        it_b->second.q_socket.push(std::make_pair(dst_socket, src_socket));
    }
    else if(auto it_b = binds.find(socket_t{0u, dst_socket.port}); it_b != binds.end()) {
        if(tcphdr->flags != TH_SYN) {
            fprintf(stderr, "[TCP Error] only SYN can be sent to bind. %s\n",
                    debugSegmentSummary(iphdr, tcphdr, payload_len).c_str());
        }
        // wildcard bind
        Connection &conn = init_connection(dst_socket, src_socket, STATUS_LISTEN);
        conn.q_thread.push(recv_segment_lambda);
        it_b->second.q_socket.push(std::make_pair(dst_socket, src_socket));
    }
    else {
        fprintf(stderr, "[TCP Error] TCP segment not corresponding to any socket: %s\n",
                debugSegmentSummary(iphdr, tcphdr, payload_len).c_str());
    }
    return 0;
}
