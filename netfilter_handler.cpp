#include "netfilter_handler.h"

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

#include <cstring>
#include <vector>

#include "kpabe_server.h"
#include "kpabe_utils.h"
#include "logger.h"
#include "ssl_utils.h"

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

int netfilterCallback(const struct nlmsghdr *nlh, void *data) {
    auto *flows = reinterpret_cast<std::pair<std::map<TcpFlow, TcpFlowData>, std::vector<TcpFlowData>> *>(data);

    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    uint32_t id = 0, skbinfo;
    // struct nfgenmsg *nfg;
    uint16_t plen;

    /* Parse netlink message received from the kernel, the array of
     * attributes is set up to store metadata and the actual packet.
     */
    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    // nfg = reinterpret_cast<nfgenmsg *>(mnl_nlmsg_get_payload(nlh));

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

    /* Access packet metadata, which provides unique packet ID, hook number
     * and ethertype. See struct nfqnl_msg_packet_hdr for details.
     */
    ph = reinterpret_cast<nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));

    /* Access actual packet data length. */
    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

    /* Access actual packet data */
    uint8_t *payload = reinterpret_cast<uint8_t *>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));

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
    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    /* Kernel has truncated the packet, fetch original packet length. */
    if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen)
            printf("truncated ");
    }

    if (skbinfo & NFQA_SKB_GSO)
        printf("GSO ");

    id = ntohl(ph->packet_id);
    printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u", id, ntohs(ph->hw_protocol), ph->hook, plen);

    /* Fetch ethernet destination address. */
    if (attr[NFQA_HWADDR]) {
        struct nfqnl_msg_packet_hw *hw = reinterpret_cast<nfqnl_msg_packet_hw *>(mnl_attr_get_payload(attr[NFQA_HWADDR]));
        unsigned int hwlen = ntohs(hw->hw_addrlen);
        const unsigned char *addr = hw->hw_addr;
        unsigned int i;

        printf(", hwaddr %02x", addr[0]);
        for (i = 1; i < hwlen; i++) {
            if (i >= sizeof(hw->hw_addr)) {
                printf("[truncated]");
                break;
            }
            printf(":%02x", (unsigned char)addr[i]);
        }

        printf(" len %u", hwlen);
    }

    /*
     * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
     * The application should behave as if the checksums are correct.
     *
     * If these packets are later forwarded/sent out, the checksums will
     * be corrected by kernel/hardware.
     */
    if (skbinfo & NFQA_SKB_CSUMNOTREADY)
        printf(", checksum not ready");
    puts(")");

    auto *ip = reinterpret_cast<iphdr *>(payload);
    if (ip->protocol == IPPROTO_TCP) {
        auto *tcp = reinterpret_cast<tcphdr *>(payload + ip->ihl * 4);
        printf("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, seq num = %u\n", ip->saddr & 0xFF, (ip->saddr >> 8) & 0xFF, (ip->saddr >> 16) & 0xFF,
               (ip->saddr >> 24) & 0xFF, htons(tcp->source), ip->daddr & 0xFF, (ip->daddr >> 8) & 0xFF, (ip->daddr >> 16) & 0xFF,
               (ip->daddr >> 24) & 0xFF, htons(tcp->dest), htonl(tcp->seq));

        printf("header offset: TCP=%d, data=%d (%d relative to TCP)\n", ip->ihl * 4, ip->ihl * 4 + tcp->doff * 4, tcp->doff * 4);
        uint8_t *data = payload + ip->ihl * 4 + tcp->doff * 4;
        if (ip->ihl * 4 + tcp->doff * 4 < plen) {
            // handshake record header ?
            if (*data == 0x16 && *(data + 1) == 0x03 && *(data + 2) >= 0x01) {
                data += 3;
                // record size is represented with 2 bytes
                uint16_t record_size = *data++;
                record_size = (record_size << 8) + *data++;
                printf("tls handshake record size = %u bytes\n", record_size);
                // client hello ?
                if (*data == 0x01) {
                    ++data;
                    // client hello size is represented with 3 bytes
                    uint32_t clienthello_size = *data++;
                    clienthello_size = (clienthello_size << 8) + *data++;
                    clienthello_size = (clienthello_size << 8) + *data++;
                    printf("client hello size = %u bytes\n", clienthello_size);
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
                    printf("client hello contains %u bytes of extensions\n", extensions_size);
                    KPABE_DPVS_PUBLIC_KEY key;
                    bn_t scalar;
                    int kpabe_status = 0;
                    while (data < payload + plen) {
                        uint16_t extension_type = *data++;
                        extension_type = (extension_type << 8) + *data++;
                        uint16_t extension_size = *data++;
                        extension_size = (extension_size << 8) + *data++;
                        printf("contains extention %u\n", extension_type);
                        switch (extension_type) {
                            case 0:  // SNI extension
                                // currently contains a list of only 1 entry, so skip 3
                                // first bytes (2 bytes size + 1 byte type)
                                printf("SNI = %.*s\n", extension_size - 5, data + 5);
                                break;
                            case KPABE_PUB_KEY_EXT: {
                                printf("kpabe key size = %u\n", extension_size);
                                for (size_t j = 0; j < extension_size; ++j) {
                                    printf("%02X ", data[j]);
                                }
                                printf("\n");
                                IMemStream raw_data((char *)data, extension_size);
                                key.deserialize(raw_data);
                                kpabe_status |= 0b01;
                                break;
                            }
                            case KPABE_SCALAR_EXT: {
                                printf("kpabe scalar size = %u\n", extension_size);
                                aes_cbc_decrypt(data, extension_size, KpabeServer::scalar_key, KpabeServer::scalar_key + 16,
                                                reinterpret_cast<unsigned char *>(scalar));
                                kpabe_status |= 0b10;
                                for (size_t j = 0; j < sizeof(bn_t); ++j) {
                                    printf("%02X ", reinterpret_cast<unsigned char *>(scalar)[j]);
                                }
                                printf("\n");
                                break;
                            }
                            default:
                                break;
                        }

                        data += extension_size;
                    }

                    if (kpabe_status != 0b11) {
                        printf("client hello does not contains kpabe extensions\n");
                    } else {
                        std::cout << KpabeServer::public_key.validate_derived_key(key, scalar) << std::endl;
                        if (KpabeServer::public_key.validate_derived_key(key, scalar)) {
                            printf("client hello compiles with policy\n");
                        } else {
                            printf("client hello does not comply with policy\n");
                        }
                    }
                } else {
                    printf("payload is not a client hello (starts with %02X %02X)\n", data[0], data[1]);
                }
            } else {
                printf("payload is not a tls handshake record (starts with %02X %02X)\n", data[0], data[1]);
            }
        } else {
            printf("no data -> ACK\n");
        }
    }

    TcpFlowData tcp_data;
    tcp_data.verdict = true;
    tcp_data.packet_ids.emplace_back(id);
    flows->second.emplace_back(std::move(tcp_data));
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
    // logger::log(logger::DEBUG, "(fd ", fd, ") ", flows.second.size());
    for (TcpFlowData flow_data : flows.second) {
        for (const auto id : flow_data.packet_ids) {
            nlmsghdr *msg = nfq_nlmsg_put(write_buffer.data(), NFQNL_MSG_VERDICT, queue_num);
            nfq_nlmsg_verdict_put(msg, id, NF_ACCEPT);

            /* example to set the connmark. First, start NFQA_CT section: */
            nlattr *attr = mnl_attr_nest_start(msg, NFQA_CT);

            /* then, add the connmark attribute: */
            mnl_attr_put_u32(msg, CTA_MARK, htonl(1));
            // mnl_attr_put_u32(msg, NFQA_MARK, htonl(1));
            /* more conntrack attributes, e.g. CTA_LABELS could be set here */

            /* end conntrack section */
            mnl_attr_nest_end(msg, attr);

            if (mnl_socket_sendto(nl, msg, msg->nlmsg_len) < 0) {
                logger::log(logger::ERROR, "(fd ", fd, ") error while sending data -> ", std::strerror(errno));
                return 0;
            }
        }
    }

    flows.second.clear();
    // logger::log(logger::DEBUG, "ok");
    return 1;
}

bool NetfilterHandler::socketWantWrite() const {
    return !flows.second.empty();
}
