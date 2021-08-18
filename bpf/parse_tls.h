#ifndef PARSE_TLS_H
#define PARSE_TLS_H

#include <linux/types.h>
#include "context.h"

struct inner_tls {
  __u8 record_type;
  __u8 rversion[2];
  __u8 rlength[2];
  __u8 handshake_type;
  __u8 hversion[2];
  __u8 hlength[2];
};

static __always_inline __u32 check_is_tls_hello(struct context* ctx) {
  struct inner_tls* ptls = ctx->data_start + ctx->nh_offset;
  if (ptls + 1 > ctx->data_end) {
    return 0;
  }

  __u16 body_len = ctx->data_end - ctx->data_start - ctx->nh_offset;
  __u16 length = (((__u16)ptls->rlength[0]) << 8) | ptls->rlength[1];
  if (length != body_len - 5) {
    return 0;
  }

  if (ptls->record_type == 0x16 && ptls->handshake_type == 1) {
    return 1;
  }
  return 0;
}

#endif