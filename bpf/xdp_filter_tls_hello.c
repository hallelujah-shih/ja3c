#include <linux/types.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

#include "context.h"
#include "parse_l2.h"
#include "parse_l3.h"
#include "parse_l4.h"
#include "parse_tls.h"

struct perf_metadata {
  __u16 cookie;
  __u16 length;
} __packed;

struct bpf_map_def SEC("maps") cap_pkg = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

SEC("xdp/root")
int root(struct xdp_md* ctx) {
  // filter tls hello
  struct context inner_ctx = {
      .data_start = (void*)(long)ctx->data,
      .data_end = (void*)(long)ctx->data_end,
      .length = ctx->data_end - ctx->data,
      .nh_proto = 0,
      .nh_offset = 0,
  };

  if (parse_eth(&inner_ctx)) {
    return XDP_PASS;
  }

  __u32 rt_value = 0;
  switch (inner_ctx.nh_proto) {
    case ETH_P_IP:
      rt_value = parse_ipv4(&inner_ctx);
      break;
    case ETH_P_IPV6:
      rt_value = parse_ipv6(&inner_ctx);
      break;
    default:
      rt_value = 1;
      break;
  }

  if (rt_value) {
    return XDP_PASS;
  }

  switch (inner_ctx.nh_proto) {
    case IPPROTO_TCP:
      rt_value = parse_tcp(&inner_ctx);
      break;
    default:
      rt_value = 1;
      break;
  }

  if (rt_value) {
    return XDP_PASS;
  }

  if (check_is_tls_hello(&inner_ctx)) {
    __u64 falgs = BPF_F_CURRENT_CPU;
    __u32 pkt_len = inner_ctx.length;
    falgs |= (__u64)pkt_len << 32;
    struct perf_metadata metadata = {
        .cookie = 0xcafe,
        .length = inner_ctx.length,
    };

    bpf_perf_event_output(ctx, &cap_pkg, falgs, &metadata, sizeof(metadata));
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual BSD/GPL";
