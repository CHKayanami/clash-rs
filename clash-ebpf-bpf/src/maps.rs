use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, SockMap};
use clash_ebpf_common::{DaeParam, ParseTransportCtx, RedirectEntry, RedirectTuple};

#[map]
pub static DAE_PARAM: Array<DaeParam> = Array::with_max_entries(1, 0);

#[map]
pub static BYPASS_SRC_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
pub static BYPASS_DST_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
pub static BYPASS_SRC_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static BYPASS_DST_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static PROXY_SRC_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
pub static PROXY_DST_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
pub static PROXY_SRC_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static PROXY_DST_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static DYNAMIC_BYPASS_DST_IPS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(16384, 0);

#[map]
pub static DYNAMIC_BYPASS_DST_IP6S: LruHashMap<[u8; 16], u8> = LruHashMap::with_max_entries(4096, 0);

#[map]
pub static REDIRECT_TRACK: LruHashMap<RedirectTuple, RedirectEntry> = LruHashMap::with_max_entries(32768, 0);

/// SOCKMAP for transparent proxy listener sockets.
/// Keys: 0=TCP4, 1=TCP6, 2=UDP4, 3=UDP6
#[map]
pub static LISTEN_SOCKET_MAP: SockMap = SockMap::with_max_entries(4, 0);

/// PerCpuArray for packet transport parsing scratch memory (zero-allocation fast path).
#[map]
pub static PARSE_CTX_MAP: PerCpuArray<ParseTransportCtx> = PerCpuArray::with_max_entries(1, 0);
