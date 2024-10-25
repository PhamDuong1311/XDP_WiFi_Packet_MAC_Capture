/*mandatory include*/
#include <linux/types.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>

/*User define*/
#define MAX_ENTRIES 10240

/*structure for MAC address*/
// struct key {
//     __u8 address[6];
// };
// struct value {
//     __u64 timesAppearDest;
//     __u64 timesAppearSource;
// };

/*structure for Radiotap Header V0 Realtek 8188fu*/
struct radiotapHeader {
    __u8 rev;
    __u8 pad;
    __u8 length_1;
    __u8 length_2;
    __u32 presentFlags;
    __u8 flag;
    __u8 datarate;
    __u16 frequency;
    __u16 channelFlags;
    __u8 s2complementSignal;
    __u8 atena;
    __u16 rxFlags;
    __u16 rxFlags1;
};
/*structure for FCS & Duration/ID Address*/
struct frameControl {
    __u8 fcs[2];
};
struct durationID {
    __u8 duraID[2];
};
/*structure Address*/

struct addressNum1 {
    __u8 receiverAdd[6]; // for ack frame or clear to send etc
};
struct addressNum2 {
    __u8 sourceAdd[6]; // for request to send etc

};
struct addressNum3 {
    __u8 minorAdd[6];

};
/*structure for map*/
struct key {
    __u8 address[6];
};
struct value {
    __u64 timesAppearReceiver;
    __u64 timesAppearSource;
    __u64 timesAppearMinor;
};
/*define a BPF_MAP_TYPE_HASH*/
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct key);
 __type(value, struct value);
 __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_map_count1 SEC(".maps");

/*update HASH_MAP*/
static int updateAddress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct radiotapHeader *radio = data;
    if (data + sizeof(struct radiotapHeader) > data_end) {
        bpf_printk("ERR: checkpoint radio\n");
        return 0;
    }
    /*debug 1 - seems okay*/ 
    bpf_printk("HDR Info: %02x %02x %02x\n",radio->pad,radio->length_1,radio->length_2);

    /*MAJOR PROBLEM*/
    data = data + 24; // move on to the FCS
    struct frameControl *fcs = data;
    if (data + sizeof(struct frameControl) > data_end) {
        bpf_printk("ERR: checkpoint frameControl\n");
        return 0;
    }
    /*debug 2*/
    bpf_printk("FCS Info: %02x %02x\n",fcs->fcs[0],fcs->fcs[1]);
    data = data + sizeof(struct frameControl); // move on to the Duration/ID
    struct durationID *duraID = data;
    if (data + sizeof(struct durationID) > data_end) {
        bpf_printk("ERR: checkpoint durationID\n");
        return 0;
    }
    /*debug 3*/
    bpf_printk("DuraID Info: %02x %02x\n",duraID->duraID[0],duraID->duraID[1]);
    data = data + sizeof(struct durationID); // move on to the Address Field
 /*First Address*/ /*Receiver MAC*/  
    struct addressNum1 *addNum1 = data;
    if (data + sizeof(struct addressNum1) > data_end) {
        bpf_printk("ERR: sus packet\n");
        return 0;
    }
    struct key key;
    key.address[0] = addNum1->receiverAdd[0];
    key.address[1] = addNum1->receiverAdd[1];
    key.address[2] = addNum1->receiverAdd[2];
    key.address[3] = addNum1->receiverAdd[3];
    key.address[4] = addNum1->receiverAdd[4];
    key.address[5] = addNum1->receiverAdd[5];
    /*debug 4*/
    bpf_printk("Address Info [0]: %02x %02x %02x\n",key.address[0],key.address[1],key.address[2]);
    bpf_printk("Address Info [1]: %02x %02x %02x\n",key.address[3],key.address[4],key.address[5]);
    struct value *value = bpf_map_lookup_elem(&xdp_map_count1, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppearReceiver, 1);
    } else {
        struct value newval = {1,0,0};
        bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
    }
    data = data + sizeof(struct addressNum1); // Move on to the second address
 /*Second Address*/ /*Source MAC*/
    struct addressNum2 *addNum2 = data;
    if (data + sizeof(struct addressNum2) > data_end) {
        bpf_printk("WARNING: Packet have only 1 address\n");
        return 0;
    }
    key.address[0] = addNum2->sourceAdd[0];
    key.address[1] = addNum2->sourceAdd[1];
    key.address[2] = addNum2->sourceAdd[2];
    key.address[3] = addNum2->sourceAdd[3];
    key.address[4] = addNum2->sourceAdd[4];
    key.address[5] = addNum2->sourceAdd[5];
    value = bpf_map_lookup_elem(&xdp_map_count1, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppearSource, 1);
    } else {
        struct value newval = {0,1,0};
        bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
    }
    data = data + sizeof(struct addressNum2); // Move on to the third address
 /*Third Address*/ /*BSSID & others*/
    struct addressNum3 *addNum3 = data;
    if (data + sizeof(struct addressNum3) > data_end) {
        bpf_printk("WARNING: Packet have only 2 address\n");
        return 0;
    }
    key.address[0] = addNum3->minorAdd[0];
    key.address[1] = addNum3->minorAdd[1];
    key.address[2] = addNum3->minorAdd[2];
    key.address[3] = addNum3->minorAdd[3];
    key.address[4] = addNum3->minorAdd[4];
    key.address[5] = addNum3->minorAdd[5];
    value = bpf_map_lookup_elem(&xdp_map_count1, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppearMinor, 1);
    } else {
        struct value newval = {0,0,1};
        bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
    }
    return XDP_PASS;
}
SEC("xdp")
int ping(struct xdp_md *ctx) {
    updateAddress(ctx);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
