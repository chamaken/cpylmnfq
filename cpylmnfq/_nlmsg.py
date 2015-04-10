# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import ctypes

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl as mnl

from . import _cproto

"""nfq_verd Verdict helpers"""
# void nfq_nlmsg_verdict_put(struct nlmsghdr *nlh, int id, int verdict)
nlmsg_verdict_put = _cproto.c_nfq_nlmsg_verdict_put

# void nfq_nlmsg_verdict_put_mark(struct nlmsghdr *nlh, uint32_t mark)
nlmsg_verdict_put_mark = _cproto.c_nfq_nlmsg_verdict_put_mark

# void
# nfq_nlmsg_verdict_put_pkt(struct nlmsghdr *nlh, const void *pkt, uint32_t plen)
nlmsg_verdict_put_pkt = _cproto.c_nfq_nlmsg_verdict_put_pkt


"""nfq_cfg Config helpers"""
# void nfq_nlmsg_cfg_put_cmd(struct nlmsghdr *nlh, uint16_t pf, uint8_t cmd)
nlmsg_cfg_put_cmd = _cproto.c_nfq_nlmsg_cfg_put_cmd

# void nfq_nlmsg_cfg_put_params(struct nlmsghdr *nlh, uint8_t mode, int range)
nlmsg_cfg_put_params = _cproto.c_nfq_nlmsg_cfg_put_params

# void nfq_nlmsg_cfg_put_qmaxlen(struct nlmsghdr *nlh, uint32_t queue_maxlen)
nlmsg_cfg_put_qmaxlen = _cproto.c_nfq_nlmsg_cfg_put_qmaxlen


"""nlmsg Netlink message helper functions"""
# int nfq_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr **attr)
def nlmsg_parse(nlh):
    attrs = (ctypes.POINTER(mnl.Attribute) * (nfqnl.NFQA_MAX + 1))()
    attr_pp = ctypes.cast(attrs, ctypes.POINTER(ctypes.POINTER(netlink.Nlattr)))
    if _cproto.c_nfq_nlmsg_parse(nlh, attr_pp) != mnl.MNL_CB_OK:
        raise os_error()

    d = dict()
    for i in range(nfqnl.NFQA_MAX + 1):
        if bool(attrs[i]):
            d[i] = attrs[i].contents

    return d
