// SPDX-License-Identifier: GPL-2.0
//
// dnshijack_tc.c — eBPF TC ingress classifier
//
// Intercepts DNS queries (UDP/53).  For each (qname, qtype) pair found in
// the DNS_CACHE map, builds a DNS response in-place and redirects the packet
// back to the sender without forwarding to unbound/bind.
//
// Build:
//   clang -O2 -g -Wall -target bpf \
//         -D__TARGET_ARCH_x86 \
//         -I/usr/include/bpf \
//         -c dnshijack_tc.c -o dnshijack_tc.o
//
// The userspace loader embeds dnshijack_tc.o and uses aya to load/attach it.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ── Constants ────────────────────────────────────────────────────────────────

#define DNS_PORT        53
#define DNS_PAYLOAD_MAX 768
#define QNAME_MAX_LEN   256

// ── Map types (must match dnshijack-common/src/lib.rs) ───────────────────────

struct dns_key {
    __u8  qname[QNAME_MAX_LEN];  // wire-format, lowercased, zero-padded
    __u16 qtype;
    __u8  _pad[6];
} __attribute__((packed, aligned(8)));

struct dns_value {
    __u8  payload[DNS_PAYLOAD_MAX];  // pre-encoded DNS response (after txid)
    __u16 payload_len;
    __u8  _pad[6];
} __attribute__((packed, aligned(8)));

// ── BPF map ──────────────────────────────────────────────────────────────────
// Use legacy map metadata so userspace can load the object without BTF.
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct bpf_map_def SEC("maps") DNS_CACHE = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct dns_key),
    .value_size = sizeof(struct dns_value),
    .max_entries = 4096,
    .map_flags = 0,
};

// ── Helper: in-place IP checksum update ──────────────────────────────────────
// Incremental update for a 16-bit field change (RFC 1624).
static __always_inline __u16
csum_update(__u16 old_csum, __u16 old_val, __u16 new_val)
{
    __u32 csum = (~old_csum & 0xffff)
               + (~old_val  & 0xffff)
               + new_val;
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    return ~csum;
}

// ── TC classifier ────────────────────────────────────────────────────────────

SEC("classifier/ingress")
int dnshijack_tc(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ── Ethernet ─────────────────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // ── IPv4 (standard 20-byte header) ───────────────────────────────────────
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->ihl != 5)           // no IP options
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // ── UDP ──────────────────────────────────────────────────────────────────
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    if (udp->dest != bpf_htons(DNS_PORT))
        return TC_ACT_OK;

    // ── DNS header ───────────────────────────────────────────────────────────
    __u8 *dns = (void *)(udp + 1);
    if (dns + 12 > (__u8 *)data_end)
        return TC_ACT_OK;

    // Byte 2-3: flags.  QR bit (bit 15) must be 0 (query).
    __u16 dns_flags = ((__u16)dns[2] << 8) | dns[3];
    if (dns_flags & 0x8000)
        return TC_ACT_OK;   // already a response

    // Byte 4-5: QDCOUNT must be 1
    __u16 qdcount = ((__u16)dns[4] << 8) | dns[5];
    if (qdcount != 1)
        return TC_ACT_OK;

    // ── Parse qname ──────────────────────────────────────────────────────────
    struct dns_key key = {};
    __u8 *p = dns + 12;         // start of question section
    int   key_pos = 0;
    int   name_done = 0;

    // Walk the wire-format name.  Unrolled enough for verifier termination.
    // Max 256 iterations covers the worst-case name length.
    int label_rem = 0;

    #pragma unroll
    for (int i = 0; i < QNAME_MAX_LEN; i++) {
        if (p + 1 > (__u8 *)data_end)
            return TC_ACT_OK;
        __u8 b = *p++;

        if (label_rem == 0) {
            if (b > 63)             // compression pointer — unexpected in query
                return TC_ACT_OK;
            if (key_pos < QNAME_MAX_LEN)
                key.qname[key_pos++] = b;
            if (b == 0) { name_done = 1; break; }
            label_rem = b;
        } else {
            __u8 lc = (b >= 'A' && b <= 'Z') ? b + 32 : b;
            if (key_pos < QNAME_MAX_LEN)
                key.qname[key_pos++] = lc;
            label_rem--;
        }
    }

    if (!name_done)
        return TC_ACT_OK;

    // p now points to qtype (2 bytes) + qclass (2 bytes)
    if (p + 4 > (__u8 *)data_end)
        return TC_ACT_OK;
    __u16 qtype = ((__u16)p[0] << 8) | p[1];
    key.qtype = qtype;

    // ── Map lookup ───────────────────────────────────────────────────────────
    struct dns_value *val = bpf_map_lookup_elem(&DNS_CACHE, &key);
    if (!val)
        return TC_ACT_OK;

    __u16 payload_len = val->payload_len;
    if (payload_len == 0 || payload_len > DNS_PAYLOAD_MAX)
        return TC_ACT_OK;

    // ── Craft response ───────────────────────────────────────────────────────
    // Transaction ID (first 2 DNS bytes)
    __u16 txid = ((__u16)dns[0] << 8) | dns[1];

    // Sizes
    __u32 new_dns_len  = 2 + payload_len;         // txid + payload
    __u32 new_udp_len  = sizeof(struct udphdr) + new_dns_len;
    __u32 new_ip_total = sizeof(struct iphdr)  + new_udp_len;
    __u32 new_pkt_len  = sizeof(struct ethhdr) + new_ip_total;

    // Resize skb (extend or truncate)
    if (bpf_skb_change_tail(skb, new_pkt_len, 0) != 0)
        return TC_ACT_OK;

    // Reload pointers after resize
    data     = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    ip  = (void *)(eth + 1);
    udp = (void *)(ip  + 1);
    dns = (void *)(udp + 1);

    // Re-validate all header boundaries after skb resize so the verifier can
    // prove subsequent direct packet accesses are in-bounds.
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    if ((void *)dns + new_dns_len > data_end)
        return TC_ACT_OK;

    // ── Swap Ethernet MACs ───────────────────────────────────────────────────
    // Use skb byte helpers (instead of direct packet memcpy) for verifier-safe
    // reads/writes after tail adjustment.
    __u8 old_dst_mac[6];
    __u8 old_src_mac[6];
    if (bpf_skb_load_bytes(skb, 0, old_dst_mac, sizeof(old_dst_mac)) != 0)
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, 6, old_src_mac, sizeof(old_src_mac)) != 0)
        return TC_ACT_OK;
    if (bpf_skb_store_bytes(skb, 0, old_src_mac, sizeof(old_src_mac), 0) != 0)
        return TC_ACT_OK;
    if (bpf_skb_store_bytes(skb, 6, old_dst_mac, sizeof(old_dst_mac), 0) != 0)
        return TC_ACT_OK;

    // Any skb load/store helper can invalidate prior direct packet pointers.
    // Refresh pointers before touching packet headers directly again.
    data     = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    ip  = (void *)(eth + 1);
    udp = (void *)(ip  + 1);
    dns = (void *)(udp + 1);

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    if ((void *)dns + new_dns_len > data_end)
        return TC_ACT_OK;

    // ── Swap IP src/dst; update total length; fix checksum ───────────────────
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    __u16 old_tot_len = bpf_ntohs(ip->tot_len);
    __u16 new_tot_len_h = (__u16)new_ip_total;
    __u16 old_csum = bpf_ntohs(ip->check);
    ip->check    = bpf_htons(csum_update(old_csum, old_tot_len, new_tot_len_h));
    ip->tot_len  = bpf_htons(new_tot_len_h);

    // ── Swap UDP ports; fix length; zero checksum (valid for UDP/IPv4) ───────
    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest   = tmp_port;
    udp->len    = bpf_htons((__u16)new_udp_len);
    udp->check  = 0;  // RFC 768: 0 means "not computed"

    // ── Write DNS response ───────────────────────────────────────────────────
    // Use skb helper writes to keep verifier packet bounds reasoning simple.
    __u32 dns_off = (__u32)((__u8 *)dns - (__u8 *)data);
    __u8 txid_be[2] = { (__u8)(txid >> 8), (__u8)(txid & 0xff) };
    if (bpf_skb_store_bytes(skb, dns_off, txid_be, sizeof(txid_be), 0) != 0)
        return TC_ACT_OK;

    // Copy pre-computed payload (after txid).
    if (bpf_skb_store_bytes(skb, dns_off + 2,
                            val->payload, payload_len, 0) != 0)
        return TC_ACT_OK;

    // ── Redirect back to the ingress interface (sends the response) ──────────
    return bpf_redirect(skb->ingress_ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
