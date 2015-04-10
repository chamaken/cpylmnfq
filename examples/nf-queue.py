#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfq as nfq

log = logging.getLogger(__name__)
nl = mnl.Socket(netlink.NETLINK_NETFILTER)


def nfq_hdr_put(buf, nltype, queue_num):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS_QUEUE << 8) | nltype
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    return nlh


def nfq_send_verdict(queue_num, qid):
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_VERDICT, queue_num)
    nfq.nlmsg_verdict_put(nlh, qid, nf.NF_ACCEPT)

    nl.send_nlmsg(nlh)


@mnl.header_cb
def queue_cb(nlh, tb):
    attr = nfq.nlmsg_parse(nlh)
    nfg = nlh.get_payload_as(nfnl.Nfgenmsg)

    # if attr[nfqnl.NFQA_PACKET_HDR] is None:
    if not nfqnl.NFQA_PACKET_HDR in attr:
        print("metaheader not set", file=sys.stderr)
        return mnl.MNL_CB_ERROR

    ph = attr[nfqnl.NFQA_PACKET_HDR].get_payload_as(nfqnl.NfqnlMsgPacketHdr)
    plen = attr[nfqnl.NFQA_PAYLOAD].get_payload_len()
    # payload = attr[nfqnl.NFQA_PAYLOAD].get_payload_v()

    # if attr[nfqnl.NFQA_SKB_INFO] is not None:
    if nfqnl.NFQA_SKB_INFO in attr:
        skbinfo = socket.ntohl(attr[nfqnl.NFQA_SKB_INFO].get_u32())
    else:
        skbinfo = 0

    # if attr[nfqnl.NFQA_CAP_LEN] is not None:
    if nfqnl.NFQA_CAP_LEN in attr:
        orig_len = socket.ntohl(attr[nfqnl.NFQA_CAP_LEN].get_u32())
        if orig_len != plen:
            print("truncated ", end='')

    if skbinfo & nfqnl.NFQA_SKB_GSO != 0:
        print("GSO ", end='')

    pid = socket.ntohl(ph.packet_id)
    print("packet received (id=%u, hw=0x%04x hook=%u, payload len %u" \
              % (pid, socket.ntohs(ph.hw_protocol), ph.hook, plen), end='')
    
    # ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
    # The application should behave as if the checksums are correct.
    # 
    # If these packets are later forwarded/sent out, the checksums will
    # be corrected by kernel/hardware.
    if skbinfo & nfqnl.NFQA_SKB_CSUMNOTREADY != 0:
        print(", checksum not ready", end='')
    print(')')

    nfq_send_verdict(socket.ntohs(nfg.res_id), pid)

    return mnl.MNL_CB_OK


def main():
    if len(sys.argv) != 2:
        print("Usage: %s [queue_num]" % sys.argv[0])
        sys.exit(-1)

    queue_num = int(sys.argv[1])

    nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
    portid = nl.get_portid()

    buf = bytearray(0xffff + (mnl.MNL_SOCKET_BUFFER_SIZE / 2))

    # PF_(UN)BIND is not needed with kernels 3.8 and later
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_CONFIG, 0)
    nfq.nlmsg_cfg_put_cmd(nlh, socket.AF_INET, nfqnl.NFQNL_CFG_CMD_PF_UNBIND)
    nl.send_nlmsg(nlh)

    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_CONFIG, 0)
    nfq.nlmsg_cfg_put_cmd(nlh, socket.AF_INET, nfqnl.NFQNL_CFG_CMD_PF_BIND)
    nl.send_nlmsg(nlh)

    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_CONFIG, queue_num)
    nfq.nlmsg_cfg_put_cmd(nlh, socket.AF_INET, nfqnl.NFQNL_CFG_CMD_BIND)
    nl.send_nlmsg(nlh)

    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_CONFIG, queue_num)
    nfq.nlmsg_cfg_put_params(nlh, nfqnl.NFQNL_COPY_PACKET, 0xffff)
    nlh.put_u32(nfqnl.NFQA_CFG_FLAGS, socket.htonl(nfqnl.NFQA_CFG_F_GSO))
    nlh.put_u32(nfqnl.NFQA_CFG_MASK, socket.htonl(nfqnl.NFQA_CFG_F_GSO))
    nl.send_nlmsg(nlh)

    # ENOBUFS is signalled to userspace when packets were lost
    # on kernel side.  In most cases, userspace isn't interested
    # in this information, so turn it off.
    nl.setsockopt(netlink.NETLINK_NO_ENOBUFS, bytearray([1]))

    while True:
        ret = nl.recv_into(buf)
        ret = mnl.cb_run(buf[:ret], 0, portid, queue_cb, None)

    nl.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
