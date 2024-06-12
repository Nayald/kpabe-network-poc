#include "netfilter_handler.h"

#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <sys/socket.h>

extern "C" {
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* NFQA_CT requires CTA_* attributes defined in nfnetlink_conntrack.h */
#include <linux/netfilter/nfnetlink_conntrack.h>
}

#include <chrono>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "kpabe_client.h"
#include "kpabe_utils.h"
#include "logger.h"
#include "ssl_utils.h"

size_t std::hash<TcpFlow>::operator()(const TcpFlow &v) const {
    size_t result = v.src_addr >> 16;
    result *= v.src_port;
    return (result << 32) + v.dst_addr;
};

bool operator==(const TcpFlow &l, const TcpFlow &r) {
    return memcmp(&l, &r, sizeof(TcpFlow)) == 0;
}

bool operator<(const TcpFlow &l, const TcpFlow &r) {
    return memcmp(&l, &r, sizeof(TcpFlow)) < 0;
}

NetfilterException::NetfilterException(std::string msg) : msg(std::move(msg)) {
}

NetfilterHandler::NetfilterHandler(SocketHandlerManager &manager, int queue_num)
        : SocketHandlerManager::SocketHandler(manager, 0, {}, nullptr, false), queue_num(queue_num) {
    // from https://git.netfilter.org/libnetfilter_queue/tree/examples/nf-queue.c
    // Set up netlink socket to communicate with the netfilter subsystem.
    read_buffer.resize(65536 + MNL_SOCKET_BUFFER_SIZE);
    write_buffer.resize(MNL_SOCKET_BUFFER_SIZE);
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) {
        throw NetfilterException("failed to open netfilter socket");
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw NetfilterException("failed to bind netfilter socket");
    }

    portid = mnl_socket_get_portid(nl);

    /* Configure the pipeline between kernel and userspace, build and send
     * a netlink message to specify queue number to bind to. Your ruleset
     * has to use this queue number to deliver packets to userspace.
     */
    nlmsghdr *nlh = nfq_nlmsg_put(read_buffer.data(), NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw NetfilterException("failed to send message?");
    }

    /* Build and send a netlink message to specify how many bytes are
     * copied from kernel to userspace for this queue.
     */
    nlh = nfq_nlmsg_put(read_buffer.data(), NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 65536);

    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw NetfilterException("failed to send message?");
    }

    /* ENOBUFS is signalled to userspace when packets were lost
     * on kernel side.  In most cases, userspace isn't interested
     * in this information, so turn it off.
     */
    int val = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &val, sizeof(val));
    fd = mnl_socket_get_fd(nl);
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        logger::log(logger::WARNING, "(fd ", fd, ") unable to set client socket non-blocking state -> ", std::strerror(errno));
    }

    logger::log(logger::DEBUG, "(fd ", fd, ") role is NetfilterHandler");
}

NetfilterHandler::~NetfilterHandler() {
    mnl_socket_close(nl);
}

bool isKpabeCompliant(const uint8_t *data, size_t size) {
    // skip 2 bytes client version
    // skip 32 bytes client random
    data += 34;
    // skip n bytes session id, size is represented wth 1 byte
    data += *data++;
    // skip n bytes of cipher suite, size is represented with 2 bytes
    uint16_t cipher_size = *data++;
    cipher_size = (cipher_size << 8) + *data++;
    data += cipher_size;
    // skip n bytes of compression methods, size is represented with 1 byte
    data += *data++;
    // parse extensions, size is 2 bytes
    uint16_t extensions_size = *data++;
    extensions_size = (extensions_size << 8) + *data++;
    KPABE_DPVS_PUBLIC_KEY key;
    ZP scalar;
    int kpabe_status = 0;
    const uint8_t *const extension_end = data + extensions_size;
    while (data < extension_end) {
        uint16_t extension_type = *data++;
        extension_type = (extension_type << 8) + *data++;
        uint16_t extension_size = *data++;
        extension_size = (extension_size << 8) + *data++;
        logger::log(logger::DEBUG, "found extention ", extension_type);
        switch (extension_type) {
            case 0:
                // SNI extension currently contains a list of only 1 entry, so skip 3 first bytes (2 bytes size + 1 byte type)
                // we can also skip size of the entry (2 bytes) as it is all the remaining bytes
                logger::log(logger::DEBUG, "\tSNI = ", std::string_view(reinterpret_cast<const char *>(data) + 5, extension_size - 5));
                break;
            case KPABE_PUB_KEY_EXT: {
                logger::log(logger::DEBUG, "\tkpabe key size = ", extension_size);
                std::vector<unsigned char> raw_data(data, data + extension_size);
                key.deserialize(raw_data);
                kpabe_status |= 0b01;
                break;
            }
            case KPABE_SCALAR_EXT: {
                logger::log(logger::DEBUG, "\tkpabe scalar size = ", extension_size);
                ByteString raw_scalar;
                raw_scalar.resize(extension_size);
                int size = aes_cbc_decrypt(data, extension_size, KpabeClient::scalar_key, KpabeClient::scalar_key + 16, raw_scalar.data());
                if (size < 0) {
                    logger::log(logger::DEBUG, "fail to decrypt scalar");
                    return false;
                }

                raw_scalar.resize(size);
                scalar.deserialize(raw_scalar);
                kpabe_status |= 0b10;
                break;
            }
            default:
                logger::log(logger::DEBUG, "\tignored, size = %u\n", extension_size);
                break;
        }

        data += extension_size;
    }

    return kpabe_status == 0b11 && KpabeClient::public_key.validate_derived_key(key, scalar);
}

int netfilterCallback(const struct nlmsghdr *nlh, void *data) {
    auto *const flows = reinterpret_cast<std::pair<std::unordered_map<TcpFlow, TcpFlowData>, std::vector<std::pair<bool, uint32_t>>> *>(data);

    struct nlattr *attr[NFQA_MAX + 1] = {};

    /* Parse netlink message received from the kernel, the array of
     * attributes is set up to store metadata and the actual packet.
     */
    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        logger::log(logger::ERROR, "error occurs during packet parsing");
        return MNL_CB_ERROR;
    }

    // nfg = reinterpret_cast<nfgenmsg *>(mnl_nlmsg_get_payload(nlh));

    if (attr[NFQA_PACKET_HDR] == NULL) {
        logger::log(logger::ERROR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    /* Access packet metadata, which provides unique packet ID, hook number
     * and ethertype. See struct nfqnl_msg_packet_hdr for details.
     */
    const nfqnl_msg_packet_hdr *const ph = reinterpret_cast<nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));

    /* Access actual packet data length. */
    const uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

    /* Access actual packet data */
    const uint8_t *const payload = reinterpret_cast<uint8_t *>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));

    /* Fetch metadata flags, possible flags values are:
     *
     * - NFQA_SKB_CSUMNOTREADY:
     *	Kernel performed partial checksum validation, see CHECKSUM_PARTIAL.
     * - NFQA_SKB_CSUM_NOTVERIFIED:
     *	Kernel already verified checksum.
     * - NFQA_SKB_GSO:
     *	Not the original packet received from the wire. Kernel has
     *	aggregated several packets into one single packet via GSO.
     */
    const uint32_t skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    /* Kernel has truncated the packet, fetch original packet length. */
    if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen) {
            logger::log(logger::WARNING, "received packet is truncated");
        }
    }

    if (skbinfo & NFQA_SKB_GSO) {
        logger::log(logger::INFO, "received packet is an aggregate of multiple packets (GSO)");
    }

    const uint32_t id = ntohl(ph->packet_id);
    const auto *const ip = reinterpret_cast<const iphdr *>(payload);
    if (ip->protocol != IPPROTO_TCP) {
        // only handle tcp = forward
        flows->second.emplace_back(true, id);
        return MNL_CB_OK;
    }

    const auto *const tcp = reinterpret_cast<const tcphdr *>(payload + ip->ihl * 4);
    const TcpFlow tcp_flow = {ip->saddr, ip->daddr, tcp->source, tcp->dest};
    const size_t headers_size = ip->ihl * 4 + tcp->doff * 4;
    if (headers_size >= plen) {
        // no data = forward
        if (tcp->syn) {
            flows->first.insert_or_assign(tcp_flow, TcpFlowData{-1, ntohl(tcp->seq) + 1});
        }

        if (tcp->fin) {
            flows->first.erase(tcp_flow);
        }

        flows->second.emplace_back(true, id);
        return MNL_CB_OK;
    }

    auto it = flows->first.find(tcp_flow);
    if (it == flows->first.end()) {
        // no struct = drop
        flows->second.emplace_back(false, id);
        return MNL_CB_OK;
    }

    if (it->second.verdict >= 0) {
        // if a verdict already occurs = follow verdict
        flows->second.emplace_back(it->second.verdict, id);
        return MNL_CB_OK;
    }

    const uint8_t *const tcp_payload = payload + headers_size;
    const size_t tcp_payload_size = plen - headers_size;
    if (ntohl(tcp->seq) < it->second.next_seq_num) {
        // already seen segment
        flows->second.emplace_back(true, id);
        return MNL_CB_OK;
    }

    it->second.segments.try_emplace(ntohl(tcp->seq), tcp_payload, tcp_payload + tcp_payload_size);
    // reconstruct tcp stream
    auto segment_it = it->second.segments.find(it->second.next_seq_num);
    while (segment_it != it->second.segments.end()) {
        it->second.stream.insert(it->second.stream.end(), segment_it->second.begin(), segment_it->second.end());
        it->second.next_seq_num += segment_it->second.size();
        it->second.segments.erase(segment_it);
        segment_it = it->second.segments.find(it->second.next_seq_num);
    }

    auto stream_it = it->second.stream.cbegin();
    static constexpr uint16_t TLS_RECORD_SIZE = 5;
    while (it->second.stream.cend() - stream_it >= TLS_RECORD_SIZE) {
        if (*stream_it != 0x16) {
            // only allow TLS handshake records until end of clienthello
            if (it->second.clienthello_data.size() < 4 || it->second.clienthello_data.front() != 0x01) {
                // stream probably contains something not expected
                it->second = {false, 0};
                flows->second.emplace_back(it->second.verdict, id);
                return MNL_CB_OK;
            }

            break;
        }

        // ignore TLS version (2 Bytes)
        uint16_t record_size = *(stream_it + 3);
        record_size = (record_size << 8) + *(stream_it + 4);
        if (it->second.stream.cend() - stream_it < TLS_RECORD_SIZE + record_size) {
            // not enough data
            it->second.stream.erase(it->second.stream.cbegin(), stream_it);  // trim read data
            flows->second.emplace_back(true, id);
            return MNL_CB_OK;
        }

        auto record_payload_start = stream_it + TLS_RECORD_SIZE;
        it->second.clienthello_data.insert(it->second.clienthello_data.cend(), record_payload_start, stream_it += TLS_RECORD_SIZE + record_size);
    }

    uint32_t clienthello_size = it->second.clienthello_data[1];
    clienthello_size = (clienthello_size << 8) + it->second.clienthello_data[2];
    clienthello_size = (clienthello_size << 8) + it->second.clienthello_data[3];
    static constexpr uint32_t CLIENTHELLO_HEADER_SIZE = 4;
    if (it->second.clienthello_data.size() < CLIENTHELLO_HEADER_SIZE + clienthello_size) {
        // not enough data
        it->second.stream.erase(it->second.stream.cbegin(), stream_it);  // trim read data
        flows->second.emplace_back(true, id);
        return MNL_CB_OK;
    }

    // equivalent to free all as when verdict is >= 0 all other member are meaningless
    const auto start = std::chrono::steady_clock::now();
    it->second = {isKpabeCompliant(it->second.clienthello_data.data() + CLIENTHELLO_HEADER_SIZE, clienthello_size), 0};
    logger::log(logger::INFO, "verification took ", std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start));
    logger::log(logger::INFO, ip->saddr & 0xFF, '.', (ip->saddr >> 8) & 0xFF, '.', (ip->saddr >> 16) & 0xFF, '.', (ip->saddr >> 24) & 0xFF, ':',
                htons(tcp->source), " -> ", ip->daddr & 0xFF, '.', (ip->daddr >> 8) & 0xFF, '.', (ip->daddr >> 16) & 0xFF, '.',
                (ip->daddr >> 24) & 0xFF, ':', htons(tcp->dest), " clienthello ", it->second.verdict ? "is" : "isn't", " compliant");
    flows->second.emplace_back(it->second.verdict, id);
    return MNL_CB_OK;
}

int NetfilterHandler::handleSocketRead() {
    int size = mnl_socket_recvfrom(nl, read_buffer.data(), read_buffer.size());
    while (size > 0) {
        if (mnl_cb_run(read_buffer.data(), size, 0 /* seq */, portid, netfilterCallback, &flows) < 0) {
            logger::log(logger::ERROR, "(fd ", fd, ") got error -> ", std::strerror(errno));
            return 0;
        }

        size = mnl_socket_recvfrom(nl, read_buffer.data(), read_buffer.size());
    }

    if (size < 0 && errno != EAGAIN) {
        if (errno != ENOBUFS) {
            logger::log(logger::ERROR, "(fd ", fd, ") got error -> ", std::strerror(errno));
            return 0;
        }
    }

    return 1;
}

int NetfilterHandler::handleSocketWrite() {
    for (const auto &[verdict, id] : flows.second) {
        nlmsghdr *msg = nfq_nlmsg_put(write_buffer.data(), NFQNL_MSG_VERDICT, queue_num);
        // printf("id: %d, verdict: %d\n", id, verdict);
        nfq_nlmsg_verdict_put(msg, id, verdict ? NF_ACCEPT : NF_DROP);

        /* example to set the connmark. First, start NFQA_CT section: */
        nlattr *attr = mnl_attr_nest_start(msg, NFQA_CT);

        /* then, add the connmark attribute: */
        // mnl_attr_put_u32(msg, CTA_MARK, htonl(1));
        // mnl_attr_put_u32(msg, NFQA_MARK, htonl(1));
        /* more conntrack attributes, e.g. CTA_LABELS could be set here */

        /* end conntrack section */
        mnl_attr_nest_end(msg, attr);

        if (mnl_socket_sendto(nl, msg, msg->nlmsg_len) < 0) {
            logger::log(logger::ERROR, "(fd ", fd, ") error while sending data -> ", std::strerror(errno));
            return 0;
        }
    }

    flows.second.clear();
    // logger::log(logger::DEBUG, "ok");
    return 1;
}

bool NetfilterHandler::socketWantWrite() const {
    return !flows.second.empty();
}
