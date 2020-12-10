#include "tcp_internal.hpp"
#include "socket_wrapper.hpp"
#include <arpa/inet.h>
#include <cstring>

void tcp_conn_recv_segment(socket_t src, socket_t dest, Connection &conn,
                           const void *iphdr /* ip packet */, const void *tcpbuf,
                           int payload_len /* payload len */) {
    conn.q_thread.clearTimeout(conn.timer_keepalive);
    conn.timer_keepalive = conn.q_thread.setTimeout(kill_connection, TIMEOUT_KEEPALIVE);
    
    const tcp_header_t *tcphdr = (const tcp_header_t *)tcpbuf;
    std::string segsummary = debugSegmentSummary(iphdr, tcpbuf, payload_len);
    
    switch(conn.status) {
    case STATUS_CLOSE_WAIT:
    case STATUS_CLOSED:
    case STATUS_TERMINATED:
    case STATUS_TERMINATED_FREED:
        /*
         * For not open or already closed states, we drop all segments received.
         */
        fprintf(stderr, "[TCP Error] drop segment: connection invalidated. %s\n", segsummary.c_str());
        break;
        
    case STATUS_LISTEN:
    listen_syn:
        /*
         * For LISTEN, we are expecting a SYN.
         * From this SYN, we can get the remote sequence number.
         * We reply the remote with our sequence number.
         * In fact, we should have our sequence number += 1. However,
         * as we may need to resend it in our state machine,
         * to prevent it from being += 1 multiple times,
         * we just send seq-1 to remote.
         */
        if(tcphdr->flags != TH_SYN) {
            fprintf(stderr, "[TCP Error] drop segment: listening only to SYN. %s\n",
                    segsummary.c_str());
            break;
        }
        conn.ack = tcphdr->seq + 1;
        sendTCPSegment(src, dest, TH_SYN | TH_ACK, conn.seq - 1, conn.ack, NULL, 0);
        conn.status = STATUS_SYN_RCVD;
        fprintf(stderr, "received SYN. sent SYN/ACK. %s\n",
                segsummary.c_str());
        break;
        
    case STATUS_SYN_SENT:
        /*
         * For SYN_SENT, we are trying to create the connection actively.
         * we expect receiving a peer SYN or a SYN/ACK and get remote sequence number.
         * for case where there is a SYN, we send ACK in response, but expect another ACK later.
         * for SYN/ACK received (common case), we send ACK and establish the connection.
         */
        if(tcphdr->flags == TH_SYN) {
            conn.ack = tcphdr->seq + 1;
            sendTCPSegment(src, dest, TH_ACK, conn.seq, conn.ack, NULL, 0);
            conn.status = STATUS_SYN_RCVD;
            fprintf(stderr, "received peer SYN. sending ACK. %s\n",
                    segsummary.c_str());
            break;
        }
        else if(tcphdr->flags == (TH_SYN | TH_ACK)) {
            if(tcphdr->ack != conn.seq) {
                fprintf(stderr, "[TCP Error] drop segment: synack incorrect ack. %s\n",
                        segsummary.c_str());
                break;
            }
            conn.ack = tcphdr->seq + 1;
            sendTCPSegment(src, dest, TH_ACK, conn.seq, conn.ack, NULL, 0);
            conn.status = STATUS_ESTAB;
            fprintf(stderr, "received SYN/ACK. sending ACK. connection established. %s\n",
                    segsummary.c_str());
            conn.cond_socket.set();    // unblock socket API connect() and let it return 0
            break;
        }
        else {
            fprintf(stderr, "[TCP Error] drop segment: SYN_SENT accepting only SYN or SYN/ACK. %s\n",
                    segsummary.c_str());
            break;
        }

    case STATUS_SYN_RCVD:
        /*
         * For SYN_RCVD, we expect an ACK. 
         * We will rigorously check the ACK number to ensure it's the right connection.
         * From this ACK on (inclusive), data payload is possible.
         */
        if(tcphdr->flags == TH_SYN) goto listen_syn;
        if((tcphdr->flags & TH_ACK) == 0 || tcphdr->ack != conn.seq) {
            fprintf(stderr, "[TCP Error] drop segment: no valid ACK. %s\n",
                    segsummary.c_str());
            break;
        }
        if(tcphdr->seq != conn.ack) {
            fprintf(stderr, "[TCP Error] drop segment: wrong ACK, not establishing conn. %s\n",
                    segsummary.c_str());
            break;
        }
        conn.status = STATUS_ESTAB;
        fprintf(stderr, "received ACK of SYN. connection established. %s\n",
                segsummary.c_str());
        conn.cond_socket.set();    // unblock socket API connect() and let it return 0
        goto process_normal_segment;   // deal with the data payload

    case STATUS_ESTAB:
        if(tcphdr->seq == conn.ack && (tcphdr->flags & TH_FIN)) {
            conn.status = STATUS_CLOSE_WAIT;
            conn.cond_socket.set();  // send EOF
        }
        goto process_normal_segment;

    case STATUS_FIN_WAIT_1:
        /*
         * For FIN_WAIT_1, we have actively sent our FIN.
         * If acked by remote side, we can move on to next stage.
         * The remote may also send FIN back, which we may acknowledge.
         */
        if(tcphdr->ack == conn.seq) {
            // receive ACK of FIN
            if(tcphdr->seq == conn.ack && (tcphdr->flags & TH_FIN)) {
                conn.status = STATUS_TERMINATED;
                fprintf(stderr, "received ACK of FIN and remote FIN. connection terminated. %s\n",
                        segsummary.c_str());
                conn.cond_socket.set();  // send EOF and close
            }
            else {
                conn.status = STATUS_FIN_WAIT_2;
                fprintf(stderr, "received ACK of FIN. waiting for remote to close connection. %s\n",
                        segsummary.c_str());
            }
        }
        else if(tcphdr->ack == conn.seq) {
            // receive a normal ACK, and our FIN not yet arrived at remote
            if(tcphdr->seq == conn.ack && (tcphdr->flags & TH_FIN)) {
                conn.status = STATUS_LAST_ACK;
                fprintf(stderr, "received remote FIN. waiting for ACK of our FIN. %s\n",
                        segsummary.c_str());
                conn.cond_socket.set();       // received remote FIN, announcing EOF
            }
        }
        goto process_normal_segment;

    case STATUS_FIN_WAIT_2:
        /*
         * For FIN_WAIT_2, we have received ACK of our FIN, thus closing half connection.
         * We just need to wait for the other side to finish sending data.
         */
        if((tcphdr->flags & TH_FIN) && tcphdr->seq == conn.ack) {
            conn.status = STATUS_TERMINATED;
            fprintf(stderr, "received remote FIN. connection terminated. %s\n",
                    segsummary.c_str());
            conn.cond_socket.set();
            // don't need to send ACK here. ACK will be sent at process_normal_segment.
        }
        goto process_normal_segment;

    case STATUS_LAST_ACK:
        /*
         * For LAST_ACK, we are expecting an ACK of our FIN.
         */
        if(tcphdr->ack == conn.seq) {
            conn.status = STATUS_TERMINATED;
            fprintf(stderr, "received ACK of FIN. connection terminated. %s\n",
                    segsummary.c_str());
            conn.cond_socket.set();   // send EOF and close
            break;
        }
        goto process_normal_segment;
        
    process_normal_segment:
        if(tcphdr->flags & TH_SYN) {
            fprintf(stderr, "[TCP Error] drop segment: not accepting syn as normal. %s\n",
                    segsummary.c_str());
            break;
        }
        // NOTIMPLEMENTED: TH_PSH. We always give data to socket API at once without buffering anymore.
        // NOTIMPLEMENTED: sending ACK with hitchhike data payload
        
        // apply acknowledgement
        while(!conn.q_sent.empty() &&
              (int64_t)((uint64_t)tcphdr->ack -
                        (uint64_t)(conn.q_sent.front().seq + conn.q_sent.front().len))
              >= 0) {
            conn.q_thread.clearTimeout(conn.q_sent.front().timer_retransmission);
            conn.q_sent.pop();
        }
        
        // receive data payload and send ACK if required.
        // ACK is required if FIN is set or there is a non-empty data payload
        if(tcphdr->seq == conn.ack) {
            if(payload_len) {
                conn.ack += payload_len;
                const uint8_t *payload = (const uint8_t *)tcpbuf + 4 * (tcphdr->data_offset >> 4);
#ifdef RUNTIME_INTERPOSITION
                init_reals();
#endif
                __real_write(conn.q_socket_fd, payload, payload_len);
            }
            if(TH_FIN & tcphdr->flags) ++conn.ack;
            if((TH_FIN & tcphdr->flags) || payload_len) {
                sendTCPSegment(src, dest, TH_ACK,
                               conn.seq, conn.ack,
                               NULL, 0);
            }
        }
        else {
            // NOTIMPLEMENTED: selective ack, and buffering out-of-order segments
            fprintf(stderr, "[TCP Error] out-of-order segment %s\n",
                    segsummary.c_str());
        }
        break;

    default:
        fprintf(stderr, "[TCP Error] ERROR: UNKNOWN STATE (%d) WHEN RECEIVING PACKET. %s\n",
                conn.status,
                segsummary.c_str());
    }
    
    if(tcphdr->flags & TH_RST) {
        /*
         * If RST is received, unconditionally terminate the connection.
         */
        kill_connection(src, dest, conn);
        fprintf(stderr, "Received RST. closing connection. %s\n",
                segsummary.c_str());
        return;
    }
}
