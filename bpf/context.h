#ifndef CONTEXT_H
#define CONTEXT_H

#include <linux/types.h>

struct context {
  void* data_start;
  void* data_end;
  __u32 length;

  __u32 nh_proto;
  __u32 nh_offset;
};

#endif // !CONTEXT_H