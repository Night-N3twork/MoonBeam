#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#define NO_SYS 1
/* lwip defaults to 1, which lets its heap and pools hand out unaligned
 * structs; Rust (and wasm atomics) expect natural alignment */
#define MEM_ALIGNMENT 4
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_RAW 1

#define LWIP_TIMERS 1
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#define MEM_SIZE 2097152
#define ARP_QUEUEING 1
#define IP_REASS_MAX_PBUFS 10
#define LWIP_TCP 1
#define TCP_MSS 1460
#define TCP_WND (4 * TCP_MSS)
#define TCP_SND_BUF (4 * TCP_MSS)

#endif