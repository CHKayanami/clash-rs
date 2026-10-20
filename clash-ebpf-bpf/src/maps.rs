use crate::transport::ParsedPacket;
use crate::tracking::{Scratch};
use aya_ebpf::btf_maps::{
    Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf, SkStorage, SockMap,
};
use aya_ebpf::macros::btf_map;
use clash_ebpf_common::{
    DaeEvent, DaeParam, FlowTrackEntry, PIDName, ParseTransportCtx,
    RedirectTuple, UdpReplyKey, UdpReplyEntry, TrackingGcBatch, tracking::gate::BUCKETS,
};

#[btf_map]
pub static DAE_PARAM: Array<DaeParam, 1> = Array::new();

// Userspace overrides these minimal capacities before creating the maps.
#[btf_map]
pub static BYPASS_SRC_PORTS: HashMap<u16, u8, 1> = HashMap::new();

#[btf_map]
pub static BYPASS_DST_PORTS: HashMap<u16, u8, 1> = HashMap::new();

#[btf_map]
pub static BYPASS_SRC_IPS: LpmTrie<u32, u8, 1> = LpmTrie::new();

#[btf_map]
pub static BYPASS_SRC_IP6S: LpmTrie<[u8; 16], u8, 1> = LpmTrie::new();

#[btf_map]
pub static BYPASS_DST_IPS: LpmTrie<u32, u8, 1> = LpmTrie::new();

#[btf_map]
pub static BYPASS_DST_IP6S: LpmTrie<[u8; 16], u8, 1> = LpmTrie::new();

#[btf_map]
pub static PROXY_SRC_PORTS: HashMap<u16, u8, 256> = HashMap::new();

#[btf_map]
pub static PROXY_DST_PORTS: HashMap<u16, u8, 256> = HashMap::new();

#[btf_map]
pub static PROXY_SRC_IPS: LpmTrie<u32, u8, 1024> = LpmTrie::new();

#[btf_map]
pub static PROXY_SRC_IP6S: LpmTrie<[u8; 16], u8, 1024> = LpmTrie::new();

#[btf_map]
pub static PROXY_DST_IPS: LpmTrie<u32, u8, 1024> = LpmTrie::new();

#[btf_map]
pub static PROXY_DST_IP6S: LpmTrie<[u8; 16], u8, 1024> = LpmTrie::new();

#[btf_map]
pub static PROXY_SRC_MACS: HashMap<[u8; 6], u8, 1024> = HashMap::new();

#[btf_map]
pub static DYNAMIC_BYPASS_DST_IPS: LruHashMap<u32, u8, 16384> = LruHashMap::new();

#[btf_map]
pub static DYNAMIC_BYPASS_DST_IP6S: LruHashMap<[u8; 16], u8, 16384> =
    LruHashMap::new();

// NO_PREALLOC publishes route/generation as immutable replacement allocations.
// Mutable activity and every lifecycle change follow the bucket protocol.
#[btf_map]
pub static FLOW_TRACK: HashMap<RedirectTuple, FlowTrackEntry, 98304, 1> = HashMap::new();

#[btf_map]
pub static FLOW_SCRATCH: PerCpuArray<Scratch, 1> = PerCpuArray::new();

#[btf_map]
pub static TRACKING_GATES: Array<u64, { BUCKETS as usize }> = Array::new();

#[btf_map]
pub static TRACKING_GC_REQUEST: Array<TrackingGcBatch, 1> = Array::new();

/// Non-preallocated client-socket routes. Requests, reply refreshes and BPF collection
/// share the client bucket; userspace only supplies conditional GC candidates.
#[btf_map]
pub static UDP_REPLY_TRACK: HashMap<UdpReplyKey, UdpReplyEntry, 32768, 1> =
    HashMap::new();

/// Transparent proxy listeners: TCP4, TCP6, UDP4, UDP6.
#[btf_map]
pub static LISTEN_SOCKET_MAP: SockMap<4> = SockMap::new();

/// PerCpuArray for nonlinear packet parsing scratch memory (slow path only).
#[btf_map]
pub static PARSE_CTX_MAP: PerCpuArray<ParseTransportCtx, 1> = PerCpuArray::new();

/// Socket cookie to PID and process name mapping (populated by cgroup socket hooks).
#[btf_map]
pub static COOKIE_PID_MAP: HashMap<u64, PIDName, 65536> = HashMap::new();

/// Active TCP socket decision: 1=unclassified, 2=proxy, 3=direct.
/// Socket-local storage survives flow-LRU eviction and is freed with the socket.
#[btf_map]
pub static TCP_SOCKET_POLICY: SkStorage<u32> = SkStorage::new();

/// Process whitelist for local traffic proxying (comm name matching).
#[btf_map]
pub static PROXY_PROCESSES: HashMap<[u8; 16], u8, 256> = HashMap::new();

/// Process blacklist for local traffic bypassing (comm name matching).
#[btf_map]
pub static BYPASS_PROCESSES: HashMap<[u8; 16], u8, 256> = HashMap::new();

/// DSCP values blacklist for direct bypassing.
#[btf_map]
pub static BYPASS_DSCPS: HashMap<u8, u8, 64> = HashMap::new();

/// FWMark values blacklist for direct bypassing.
#[btf_map]
pub static BYPASS_FWMARKS: HashMap<u32, u8, 256> = HashMap::new();

/// RingBuffer for sending events and alerts from eBPF to userspace.
#[btf_map]
pub static EVENT_RINGBUF: RingBuf<DaeEvent, 262144> = RingBuf::new();

/// PerCpuArray for parsed packet scratch memory (zero stack allocation).
#[btf_map]
pub static PARSED_PKT_MAP: PerCpuArray<ParsedPacket, 1> = PerCpuArray::new();
