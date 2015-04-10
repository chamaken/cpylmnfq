# -*- coding: utf-8 -*-

from __future__ import absolute_import

import errno, ctypes

from cpylmnl.linux import netlinkh as netlink

LIBNFQ = ctypes.CDLL("libnetfilter_queue.so", use_errno=True)

#
# New API based on libmnl
#

c_nfq_nlmsg_cfg_put_cmd = LIBNFQ.nfq_nlmsg_cfg_put_cmd
c_nfq_nlmsg_cfg_put_cmd.__doc__ = """\
void nfq_nlmsg_cfg_put_cmd(struct nlmsghdr *nlh, uint16_t pf, uint8_t cmd)"""
c_nfq_nlmsg_cfg_put_cmd.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_uint8]

c_nfq_nlmsg_cfg_put_params = LIBNFQ.nfq_nlmsg_cfg_put_params
c_nfq_nlmsg_cfg_put_params.__doc__ = """\
void nfq_nlmsg_cfg_put_params(struct nlmsghdr *nlh, uint8_t mode, int range)"""
c_nfq_nlmsg_cfg_put_params.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint8, ctypes.c_int]

c_nfq_nlmsg_cfg_put_qmaxlen = LIBNFQ.nfq_nlmsg_cfg_put_qmaxlen
c_nfq_nlmsg_cfg_put_qmaxlen.__doc__ = """\
void nfq_nlmsg_cfg_put_qmaxlen(struct nlmsghdr *nlh, uint32_t qmaxlen)"""
c_nfq_nlmsg_cfg_put_qmaxlen.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint32]


c_nfq_nlmsg_verdict_put = LIBNFQ.nfq_nlmsg_verdict_put
c_nfq_nlmsg_verdict_put.__doc__ = """\
void nfq_nlmsg_verdict_put(struct nlmsghdr *nlh, int id, int verdict)"""
c_nfq_nlmsg_verdict_put.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_int, ctypes.c_int]

c_nfq_nlmsg_verdict_put_mark = LIBNFQ.nfq_nlmsg_verdict_put_mark
c_nfq_nlmsg_verdict_put_mark.__doc__ = """\
void nfq_nlmsg_verdict_put_mark(struct nlmsghdr *nlh, uint32_t mark)"""
c_nfq_nlmsg_verdict_put_mark.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint32]

c_nfq_nlmsg_verdict_put_pkt = LIBNFQ.nfq_nlmsg_verdict_put_pkt
c_nfq_nlmsg_verdict_put_pkt.__doc__ = """\
void nfq_nlmsg_verdict_put_pkt(struct nlmsghdr *nlh, const void *pkt, uint32_t pktlen)"""
c_nfq_nlmsg_verdict_put_pkt.argtypes =  [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_void_p, ctypes.c_uint32]


c_nfq_nlmsg_parse = LIBNFQ.nfq_nlmsg_parse
c_nfq_nlmsg_parse.__doc__ = """\
int nfq_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr **pkt)"""
c_nfq_nlmsg_parse.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.POINTER(ctypes.POINTER(netlink.Nlattr))]
# c_nfq_nlmsg_parse.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), (ctypes.POINTER(netlink.Nlattr) * 0)]
c_nfq_nlmsg_parse.restype = ctypes.c_int


def os_error():
    """create OSError from C errno. And clear C errno"""
    en = ctypes.get_errno()
    ctypes.set_errno(0)
    if en == 0:
        return OSError(en, "(no errno found)")
    else:
        return OSError(en, errno.errorcode[en])
