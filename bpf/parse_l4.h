#ifndef PARSE_L4_H
#define PARSE_L4_H

#include <linux/tcp.h>
#include <linux/udp.h>
#include "context.h"

static __always_inline __u32 parse_udp(struct context* ctx) {
  struct udphdr* udp = ctx->data_start + ctx->nh_offset;
  if (udp + 1 > ctx->data_end) {
    return 1;
  }

  ctx->nh_offset += sizeof(*udp);
  ctx->nh_proto = 0;

  return 0;
}

static __always_inline __u32 parse_tcp(struct context* ctx) {
  struct tcphdr* tcp = ctx->data_start + ctx->nh_offset;

  if (tcp + 1 > ctx->data_end) {
    return 1;
  }

  __u16 hlen = tcp->doff << 2;
  if ((void*)tcp + hlen > ctx->data_end) {
    return 1;
  }

  ctx->nh_offset += hlen;
  ctx->nh_proto = 0;

  return 0;
}

#endif