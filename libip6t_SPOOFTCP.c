#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>

#include "xt_SPOOFTCP.h"

enum {
	O_TTL,
	O_WRONG_CHKSUM,
	O_TCP_FLAGS,
	O_INV_SEQ,
};

/* Copied from libxt_tcp.c */
struct tcp_flag_names {
	const char *name;
	__u8 flag;
};

static const struct tcp_flag_names tcp_flag_names[]
= { { "FIN", 0x01 },
    { "SYN", 0x02 },
    { "RST", 0x04 },
    { "PSH", 0x08 },
    { "ACK", 0x10 },
    { "URG", 0x20 },
    { "ALL", 0x3F },
    { "NONE", 0 },
};
#define TCP_FLAG_NAMES_SIZE 8

static __u8 parse_tcp_flag(const char *flags)
{
	__u8 ret = 0;
	char *ptr;
	char *buffer;

	buffer = strdup(flags);

	for (ptr = strtok(buffer, ","); ptr; ptr = strtok(NULL, ",")) {
		unsigned int i;
		for (i = 0; i < TCP_FLAG_NAMES_SIZE; ++i)
			if (strcasecmp(tcp_flag_names[i].name, ptr) == 0) {
				ret |= tcp_flag_names[i].flag;
				break;
			}
		if (i == TCP_FLAG_NAMES_SIZE)
			xtables_error(PARAMETER_PROBLEM,
				   "Unknown TCP flag `%s'", ptr);
	}

	free(buffer);
	return ret;
}

static void print_tcpf(__u8 flags)
{
	int have_flag = 0;

	while (flags) {
		unsigned int i;

		for (i = 0; (flags & tcp_flag_names[i].flag) == 0; i++);

		if (have_flag)
			printf(",");
		printf("%s", tcp_flag_names[i].name);
		have_flag = 1;

		flags &= ~tcp_flag_names[i].flag;
	}

	if (!have_flag)
		printf("NONE");
}

static void SPOOFTCP_help6()
{
	printf("SPOOFTCP options:\n --hoplimit value\tThe hop limit value of spoofed packet (0 for inherit)\n");
	printf(" --tcp-flags\t TCP FLAGS of spoofed packet\n");
	printf(" --corrupt-checksum\t Do not calculate checksum for spoofed packet\n");
	printf(" --corrupt-seq\t Do not generate TCP SEQ for spoofed packet\n");
}

static const struct xt_option_entry SPOOFTCP_opts[] = {
	{
		.name	= "hoplimit",
		.id		= O_TTL,
		.type	= XTTYPE_UINT8,
		.min	= 0,
		.max	= UINT8_MAX,
		.flags	= XTOPT_PUT, XTOPT_POINTER(struct xt_spooftcp_info, ttl),
	},
	{
		.name	= "corrupt-checksum",
		.id		= O_WRONG_CHKSUM,
		.type	= XTTYPE_NONE,
	},
	{
		.name	= "tcp-flags",
		.id		= O_TCP_FLAGS,
		.type	= XTTYPE_STRING,
	},
	{
		.name	= "corrupt-seq",
		.id		= O_INV_SEQ,
		.type	= XTTYPE_NONE,
	},
	XTOPT_TABLEEND,
};

static void SPOOFTCP_parse(struct xt_option_call *cb)
{
	struct xt_spooftcp_info *info = cb->data;
	const struct xt_option_entry *entry = cb->entry;

	xtables_option_parse(cb);

	switch(entry->id)
	{
		case O_TTL:
			break; // Do nothing
		case O_WRONG_CHKSUM:
			info->wrong_chksum = true;
			break;
		case O_TCP_FLAGS:
			info->tcp_flags = parse_tcp_flag(cb->arg);
			break;
		case O_INV_SEQ:
			info->inv_seq = true;
			break;
	}
}

static void SPOOFTCP_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM,
		           "SPOOFTCP target: At least one parameter is required");
}

static void SPOOFTCP_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
	const struct xt_spooftcp_info *info =
		(const struct xt_spooftcp_info *)target->data;
	if (info->ttl)
		printf(" SPOOFTCP hoplimit = %u", info->ttl);
	else
		printf(" SPOOFTCP hoplimit inherit");

	if (info->wrong_chksum)
		printf(" Corrupt checksum");

	if (info->inv_seq)
		printf(" Corrupt SEQ");

	printf(" tcp flags ");
	if (numeric)
		printf("0x%02X", info->tcp_flags);
	else
		print_tcpf(info->tcp_flags);
}

static void SPOOFTCP_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_spooftcp_info *info =
		(const struct xt_spooftcp_info *)target->data;

	if (info->ttl)
		printf(" --%s %u", SPOOFTCP_opts[O_TTL].name, info->ttl);

	if (info->wrong_chksum)
		printf(" --%s ", SPOOFTCP_opts[O_WRONG_CHKSUM].name);

	if (info->inv_seq)
		printf(" --%s ", SPOOFTCP_opts[O_INV_SEQ].name);

	printf(" --%s ", SPOOFTCP_opts[O_TCP_FLAGS].name);
	print_tcpf(info->tcp_flags);
}

static struct xtables_target spooftcp_tg6_reg = {
	.family			= NFPROTO_IPV6,
	.name			= "SPOOFTCP",
	.version		= XTABLES_VERSION,
	.size			= XT_ALIGN(sizeof(struct xt_spooftcp_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_spooftcp_info)),
	.help			= SPOOFTCP_help6,
	.print			= SPOOFTCP_print,
	.save			= SPOOFTCP_save,
	.x6_parse		= SPOOFTCP_parse,
	.x6_fcheck		= SPOOFTCP_check,
	.x6_options		= SPOOFTCP_opts,
};

void _init(void)
{
	xtables_register_target(&spooftcp_tg6_reg);
}