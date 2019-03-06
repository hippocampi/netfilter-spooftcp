#ifndef _XT_SPOOFTCP_TARGET_H
#define _XT_SPOOFTCP_TARGET_H

#include <linux/types.h>

struct xt_spooftcp_info {
    __u8 ttl;
    __u8 tcp_flags;
    __u8 corrupt_chksum;
    __u8 corrupt_seq;
    __u8 delay;
    __u8 payload_len;
    __u8 md5_header;
};

/* MD5 header size, aligned */
#define MD5_HEADER_SIZE 20

#endif /* _XT_SPOOFTCP_TARGET_H */
