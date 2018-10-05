#ifndef _XT_SPOOFTCP_TARGET_H
#define _XT_SPOOFTCP_TARGET_H

#include <linux/types.h>

struct xt_spooftcp_info {
    __u8 ttl;
    __u8 tcp_flags;
    __u8 wrong_chksum;
    __u8 inv_seq;
};

#endif /* _XT_SPOOFTCP_TARGET_H */