#ifndef __ARCH_SYS_ARCH_H__
#define __ARCH_SYS_ARCH_H__

#include "lwip/arch.h"

typedef u8_t sys_prot_t;

#define SYS_MBOX_NULL NULL
#define SYS_SEM_NULL  NULL // we shouldnt be using these anyway

#endif __ARCH_SYS_ARCH_H__