cpylmnfq
========

Python wrapper of libnetfilter_queue.

implements only ``New API based on libmnl''


sample
------

see examples


installation
------------

not prepared yet


requires
--------

* libnetfilter_queue
* Python >= 2.6
* cpylmnl (https://github.com/chamaken/cpylmnl)


links
-----

* libnetfilter_queue: http://netfilter.org/projects/libnetfilter_queue/
* nfqueue-bindings (swig): https://www.wzdftpd.net/redmine/projects/nfqueue-bindings/wiki
* NetfilterQueue: https://pypi.python.org/pypi/NetfilterQueue


comparison
----------

| original				| cpylmnfq			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| nfq_nlmsg_verdict_put			| nlmsg_verdict_put		|				|
| nfq_nlmsg_verdict_put_mark		| nlmsg_verdict_put_mark	|				|
| nfq_nlmsg_verdict_put_pkt		| nlmsg_verdict_put_pkt		|				|
| nfq_nlmsg_cfg_put_cmd			| nlmsg_cfg_put_cmd		|				|
| nfq_nlmsg_cfg_put_params		| nlmsg_cfg_put_params		|				|
| nfq_nlmsg_cfg_put_qmaxlen		| nlmsg_cfg_put_qmaxlen		|				|
| nfq_nlmsg_parse			| nlmsg_parse			| returns attr dict		|
