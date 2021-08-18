#ifndef PARSE_L3_H
#define PARSE_L3_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include "context.h"

static __always_inline __u32 parse_ipv4(struct context* ctx) {
  struct iphdr* ip = ctx->data_start + ctx->nh_offset;
  if (ip + 1 > ctx->data_end) {
    return 1;
  }

  ctx->nh_offset += ip->ihl * 4;
  ctx->nh_proto = ip->protocol;

  return 0;
}

static __always_inline __u32 parse_ipv6(struct context* ctx) {
  struct ipv6hdr* ip = ctx->data_start + ctx->nh_offset;
  if (ip + 1 > ctx->data_end) {
    return 1;
  }

  ctx->nh_offset += sizeof(*ip);
  ctx->nh_proto = ip->nexthdr;

  return 0;
}

#endif