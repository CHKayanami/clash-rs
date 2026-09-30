use crate::transport::ParsedPacket;
use aya_ebpf::btf_maps::{
    Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf, SkStorage, SockMap,
};
use aya_ebpf::macros::btf_map;
use clash_ebpf_common::{
    DaeEvent, DaeParam, DirectTrackEntry, PIDName, ParseTransportCtx, RedirectEntry,
    RedirectTuple, STATIC_BYPASS_DST_MAX_ENTRIES,
    STATIC_BYPASS_DST_PORT_MAX_ENTRIES, STATIC_BYPASS_SRC_MAX_ENTRIES,
    STATIC_BYPASS_SRC_PORT_MAX_ENTRIES,
};

#[btf_map]
pub static DAE_PARAM: Array<DaeParam, 1> = Array::new();

#[btf_map]
pub static BYPASS_SRC_PORTS: HashMap<
    u16,
    u8,
    { STATIC_BYPASS_SRC_PORT_MAX_ENTRIES as usize },
> = HashMap::new();

#[btf_map]
pub static BYPASS_DST_PORTS: HashMap<
    u16,
    u8,
    { STATIC_BYPASS_DST_PORT_MAX_ENTRIES as usize },
> = HashMap::new();

#[btf_map]
pub static BYPASS_SRC_IPS: LpmTrie<
    u32,
    u8,
    { STATIC_BYPASS_SRC_MAX_ENTRIES as usize },
> = LpmTrie::new();

#[btf_map]
pub static BYPASS_SRC_IP6S: LpmTrie<
    [u8; 16],
    u8,
    { STATIC_BYPASS_SRC_MAX_ENTRIES as usize },
> = LpmTrie::new();

#[btf_map]
pub static BYPASS_DST_IPS: LpmTrie<
    u32,
    u8,
    { STATIC_BYPASS_DST_MAX_ENTRIES as usize },
> = LpmTrie::new();

#[btf_map]
pub static BYPASS_DST_IP6S: LpmTrie<
    [u8; 16],
    u8,
    { STATIC_BYPASS_DST_MAX_ENTRIES as usize },
> = LpmTrie::new();

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

#[btf_map]
pub static REDIRECT_TRACK: LruHashMap<RedirectTuple, RedirectEntry, 32768> =
    LruHashMap::new();

/// Connection tracking map for dynamic bypass flows (TCP/UDP sessions).
#[btf_map]
pub static DIRECT_TRACK: LruHashMap<RedirectTuple, DirectTrackEntry, 65536> =
    LruHashMap::new();

/// SOCKMAP for transparent proxy listener sockets.
/// Keys: 0=TCP4, 1=TCP6, 2=UDP4, 3=UDP6
#[btf_map]
pub static LISTEN_SOCKET_MAP: SockMap<4> = SockMap::new();

/// PerCpuArray for packet transport parsing scratch memory (zero-allocation fast path).
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

/// PerCpuArray for event scratch memory (zero stack allocation).
#[btf_map]
pub static EVENT_SCRATCH_MAP: PerCpuArray<DaeEvent, 1> = PerCpuArray::new();

/// PerCpuArray for parsed packet scratch memory (zero stack allocation).
#[btf_map]
pub static PARSED_PKT_MAP: PerCpuArray<ParsedPacket, 1> = PerCpuArray::new();
