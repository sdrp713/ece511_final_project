//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#include "util/printf.h"
#include "util/regs.h"
#include "edge_syscall.h"
#include "mm/vm.h"

#include "eyrie_call.h"

struct edge_syscall {
  size_t syscall_num;
  unsigned char data[];
};

struct sbi_trap_regs* handle_interrupt(struct edge_syscall* syscall_data_ptr, size_t data_len, enclave_id eid);
void handle_syscall(struct encl_ctx* ctx);
void init_edge_internals(void);
uintptr_t dispatch_edgecall_syscall(struct edge_syscall* syscall_data_ptr,
                                    size_t data_len);

// Define this to enable printing of a large amount of syscall information
//#define USE_INTERNAL_STRACE 1

#ifdef USE_INTERNAL_STRACE
#define print_strace printf
#else
#define print_strace(...)
#endif

#endif /* syscall.h */
