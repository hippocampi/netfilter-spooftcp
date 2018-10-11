#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/version.h>
#include <linux/percpu.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/tcp.h>

#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack.h>
#endif

#include "xt_SPOOFTCP.h"

static DEFINE_PER_CPU(bool, spooftcp_active);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LGA1150");
MODULE_DESCRIPTION("Xtables: Send spoofed TCP packets");
MODULE_ALIAS("ip6t_SPOOFTCP");

static unsigned int spooftcp_tg6(struct sk_buff *oskb, const struct xt_action_param *par)
{
	if (unlikely(__this_cpu_read(spooftcp_active)))
		goto SPOOFTCP_RETURN;
	
	const struct ipv6hdr *oip6h = ipv6_hdr(oskb);

	if (unlikely((!(ipv6_addr_type(&oip6h->saddr) & IPV6_ADDR_UNICAST)) ||
	    (!(ipv6_addr_type(&oip6h->daddr) & IPV6_ADDR_UNICAST)))) {
		pr_debug("addr is not unicast.\n");
		goto SPOOFTCP_RETURN;
	}

	__be16 frag_off;
	__u8 proto = oip6h->nexthdr;
	int tcphoff = ipv6_skip_exthdr(oskb, ((u8 *)(oip6h + 1) - oskb->data),
				   &proto, &frag_off);

	if (unlikely((tcphoff < 0) || (tcphoff > oskb->len))) {
		pr_debug("Cannot get TCP header.\n");
		goto SPOOFTCP_RETURN;
	}

	const unsigned int otcplen = oskb->len - tcphoff;

	if (unlikely(proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr))) {
		pr_debug("proto(%d) != IPPROTO_TCP or too short (len = %d)\n",
			 proto, otcplen);
		goto SPOOFTCP_RETURN;
	}

	struct tcphdr *otcph;
	otcph = skb_header_pointer(oskb, tcphoff, sizeof(struct tcphdr),
				   otcph);
	
	if (unlikely(!otcph))
		goto SPOOFTCP_RETURN;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = xt_net(par);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	struct net *net = par->net;
#else
	struct net *net = dev_net(oskb->dev);
#endif

	struct dst_entry *dst = dst_clone(skb_dst(oskb));
	if (unlikely(dst->error)) {
		dst_release(dst);
		goto SPOOFTCP_RETURN;
	}
	
	unsigned int hh_len = (dst->dev->hard_header_len + 15)&~15;
	
	struct sk_buff *nskb = alloc_skb(hh_len + 15 + dst->header_len + sizeof(struct ipv6hdr)
			 + sizeof(struct tcphdr) + dst->trailer_len,
			 GFP_ATOMIC);

	if (unlikely(!nskb)) {
		net_dbg_ratelimited("cannot alloc skb\n");
		dst_release(dst);
		goto SPOOFTCP_RETURN;
	}			 

	skb_dst_set(nskb, dst);
	skb_reserve(nskb, hh_len + dst->header_len);

	skb_put(nskb, sizeof(struct ipv6hdr));
	skb_reset_network_header(nskb);
	struct ipv6hdr *ip6h = ipv6_hdr(nskb);
	// ip6_flow_hdr(ip6h, ip6_tclass(ip6_flowinfo(oip6h)), ip6_flowlabel(oip6h));
	ip6_flow_hdr(ip6h, 0, 0);
	const struct xt_spooftcp_info *info = par->targinfo;
	ip6h->hop_limit = info->ttl ? info->ttl : oip6h->hop_limit;
	ip6h->nexthdr = IPPROTO_TCP;
	ip6h->saddr = oip6h->saddr;
	ip6h->daddr = oip6h->daddr;
	nskb->protocol = htons(ETH_P_IPV6);

	skb_reset_transport_header(nskb);
	struct tcphdr *tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));

	/* Truncate to length (no data) */
	tcph->doff = sizeof(struct tcphdr)/4;
	tcph->source = otcph->source;
	tcph->dest = otcph->dest;
	/* Set flags */
	((u_int8_t *)tcph)[13] = info->tcp_flags;
	if (info->inv_seq) 
		tcph->seq = ~otcph->seq;
	else
		tcph->seq = otcph->seq;
	
	tcph->ack_seq = otcph->ack_seq;
	tcph->window = 0;
	tcph->urg_ptr = 0;

	/* Adjust TCP checksum */
	tcph->check = 0;
	tcph->check = csum_ipv6_magic(&ipv6_hdr(nskb)->saddr,
				      &ipv6_hdr(nskb)->daddr,
				      sizeof(struct tcphdr), IPPROTO_TCP,
				      csum_partial(tcph,
						   sizeof(struct tcphdr), 0));
	
	if (info->wrong_chksum)
		tcph->check = ~tcph->check;

	

#if IS_ENABLED(CONFIG_NF_CONNTRACK_IPV6)
	/* Do not track this spoofed packet */
#	if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	nf_reset(nskb);
	nf_ct_set(nskb, NULL, IP_CT_UNTRACKED);
#	else
	nf_conntrack_put(nskb->nfct);
	nskb->nfct     = &nf_ct_untracked_get()->ct_general;
	nskb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get(nskb->nfct);
#	endif
#endif
	__this_cpu_write(spooftcp_active, true);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	ip6_local_out(net, nskb->sk, nskb);
#else
	ip6_local_out(nskb);
#endif
	__this_cpu_write(spooftcp_active, false);
SPOOFTCP_RETURN:
	return XT_CONTINUE;
}

static int spooftcp_tg6_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target spooftcp_tg_reg __read_mostly = {
	.family		= NFPROTO_IPV6,
	.name		= "SPOOFTCP",
//	.checkentry	= spooftcp_tg6_check,
	.target		= spooftcp_tg6,
	.targetsize = sizeof(struct xt_spooftcp_info),
	.hooks		= 1 << NF_INET_POST_ROUTING,
	.table		= "mangle",
	.proto		= IPPROTO_TCP,
	.me			= THIS_MODULE,
};

static int __init spooftcp_tg_init(void)
{
	return xt_register_target(&spooftcp_tg_reg);
}

static void __exit spooftcp_tg_exit(void)
{
	xt_unregister_target(&spooftcp_tg_reg);
}

module_init(spooftcp_tg_init);
module_exit(spooftcp_tg_exit);
