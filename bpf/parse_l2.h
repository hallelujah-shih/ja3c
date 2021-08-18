#ifndef PARSE_L2_H
#define PARSE_L2_H

#include <linux/if_ether.h>
#include "context.h"

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

static __always_inline __u32 parse_eth(struct context* ctx) {
  struct ethhdr* eth = ctx->data_start + ctx->nh_offset;
  if (eth + 1 > ctx->data_end) {
    return 1;
  }

  ctx->nh_offset += sizeof(*eth);
  ctx->nh_proto = bpf_ntohs(eth->h_proto);

#pragma unroll
  for (int i = 0; i < 2; i++) {
    if (ctx->nh_proto == ETH_P_8021Q || ctx->nh_proto == ETH_P_8021AD) {
      struct vlan_hdr* vlan = ctx->data_start + ctx->nh_offset;
      if (vlan + 1 > ctx->data_end) {
        return 1;
      }

      ctx->nh_offset += sizeof(*vlan);
      ctx->nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
    }
  }
  return 0;
}

#endif