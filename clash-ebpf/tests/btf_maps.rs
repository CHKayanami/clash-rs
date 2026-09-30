//! Validate the actual embedded object, including BTF-derived map sizes.
//! Build clash-ebpf-bpf first, then run these ignored tests explicitly.
#![cfg(target_os = "linux")]

use aya::programs::Program;
use aya_obj::{Map, Object, generated::bpf_map_type::*};
use clash_ebpf_common::{
    DaeEvent, DaeParam, DirectTrackEntry, PIDName, ParseTransportCtx, RedirectEntry,
    RedirectTuple, STATIC_BYPASS_DST_MAX_ENTRIES,
    STATIC_BYPASS_DST_PORT_MAX_ENTRIES, STATIC_BYPASS_SRC_MAX_ENTRIES,
    STATIC_BYPASS_SRC_PORT_MAX_ENTRIES,
};
use std::mem::size_of;

const BYTECODE: &[u8] = include_bytes!(env!("CLASH_EBPF_OBJECT"));

#[test]
#[ignore = "requires freshly built eBPF bytecode"]
fn btf_map_definitions_match_userspace_abi() {
    assert!(!BYTECODE.is_empty(), "build clash-ebpf-bpf first");
    let obj = Object::parse(BYTECODE).expect("parse embedded eBPF object");
    assert!(
        obj.btf.is_some(),
        "BTF must be emitted for BTF map definitions"
    );
    // Names and metadata are the ABI used by the userspace loader. The parsed
    // packet scratch value is private to the BPF binary (None below).
    let expected = [
        (
            "DAE_PARAM",
            BPF_MAP_TYPE_ARRAY,
            1,
            4,
            Some(size_of::<DaeParam>()),
        ),
        (
            "BYPASS_SRC_PORTS",
            BPF_MAP_TYPE_HASH,
            STATIC_BYPASS_SRC_PORT_MAX_ENTRIES,
            2,
            Some(1),
        ),
        (
            "BYPASS_DST_PORTS",
            BPF_MAP_TYPE_HASH,
            STATIC_BYPASS_DST_PORT_MAX_ENTRIES,
            2,
            Some(1),
        ),
        (
            "BYPASS_SRC_IPS",
            BPF_MAP_TYPE_LPM_TRIE,
            STATIC_BYPASS_SRC_MAX_ENTRIES,
            8,
            Some(1),
        ),
        (
            "BYPASS_SRC_IP6S",
            BPF_MAP_TYPE_LPM_TRIE,
            STATIC_BYPASS_SRC_MAX_ENTRIES,
            20,
            Some(1),
        ),
        (
            "BYPASS_DST_IPS",
            BPF_MAP_TYPE_LPM_TRIE,
            STATIC_BYPASS_DST_MAX_ENTRIES,
            8,
            Some(1),
        ),
        (
            "BYPASS_DST_IP6S",
            BPF_MAP_TYPE_LPM_TRIE,
            STATIC_BYPASS_DST_MAX_ENTRIES,
            20,
            Some(1),
        ),
        ("PROXY_SRC_PORTS", BPF_MAP_TYPE_HASH, 256, 2, Some(1)),
        ("PROXY_DST_PORTS", BPF_MAP_TYPE_HASH, 256, 2, Some(1)),
        ("PROXY_SRC_IPS", BPF_MAP_TYPE_LPM_TRIE, 1024, 8, Some(1)),
        ("PROXY_SRC_IP6S", BPF_MAP_TYPE_LPM_TRIE, 1024, 20, Some(1)),
        ("PROXY_DST_IPS", BPF_MAP_TYPE_LPM_TRIE, 1024, 8, Some(1)),
        ("PROXY_DST_IP6S", BPF_MAP_TYPE_LPM_TRIE, 1024, 20, Some(1)),
        ("PROXY_SRC_MACS", BPF_MAP_TYPE_HASH, 1024, 6, Some(1)),
        (
            "DYNAMIC_BYPASS_DST_IPS",
            BPF_MAP_TYPE_LRU_HASH,
            16384,
            4,
            Some(1),
        ),
        (
            "DYNAMIC_BYPASS_DST_IP6S",
            BPF_MAP_TYPE_LRU_HASH,
            16384,
            16,
            Some(1),
        ),
        (
            "REDIRECT_TRACK",
            BPF_MAP_TYPE_LRU_HASH,
            32768,
            size_of::<RedirectTuple>(),
            Some(size_of::<RedirectEntry>()),
        ),
        (
            "DIRECT_TRACK",
            BPF_MAP_TYPE_LRU_HASH,
            65536,
            size_of::<RedirectTuple>(),
            Some(size_of::<DirectTrackEntry>()),
        ),
        ("TCP_SOCKET_POLICY", BPF_MAP_TYPE_SK_STORAGE, 0, 4, Some(4)),
        ("LISTEN_SOCKET_MAP", BPF_MAP_TYPE_SOCKMAP, 4, 4, Some(4)),
        (
            "PARSE_CTX_MAP",
            BPF_MAP_TYPE_PERCPU_ARRAY,
            1,
            4,
            Some(size_of::<ParseTransportCtx>()),
        ),
        (
            "COOKIE_PID_MAP",
            BPF_MAP_TYPE_HASH,
            65536,
            8,
            Some(size_of::<PIDName>()),
        ),
        ("PROXY_PROCESSES", BPF_MAP_TYPE_HASH, 256, 16, Some(1)),
        ("BYPASS_PROCESSES", BPF_MAP_TYPE_HASH, 256, 16, Some(1)),
        ("BYPASS_DSCPS", BPF_MAP_TYPE_HASH, 64, 1, Some(1)),
        ("BYPASS_FWMARKS", BPF_MAP_TYPE_HASH, 256, 4, Some(1)),
        ("EVENT_RINGBUF", BPF_MAP_TYPE_RINGBUF, 262144, 0, Some(0)),
        (
            "EVENT_SCRATCH_MAP",
            BPF_MAP_TYPE_PERCPU_ARRAY,
            1,
            4,
            Some(size_of::<DaeEvent>()),
        ),
        ("PARSED_PKT_MAP", BPF_MAP_TYPE_PERCPU_ARRAY, 1, 4, None),
    ];
    assert_eq!(
        obj.maps
            .values()
            .filter(|map| matches!(map, Map::Btf(_)))
            .count(),
        expected.len()
    );
    for (name, map_type, capacity, key_size, value_size) in expected {
        let map = obj
            .maps
            .get(name)
            .unwrap_or_else(|| panic!("missing map {name}"));
        let Map::Btf(btf_map) = map else {
            panic!("{name} still uses a legacy definition")
        };
        assert_eq!(map.map_type(), map_type as u32, "{name}: type");
        assert_eq!(map.max_entries(), capacity, "{name}: capacity");
        assert_eq!(map.key_size() as usize, key_size, "{name}: key ABI");
        if let Some(value_size) = value_size {
            assert_eq!(map.value_size() as usize, value_size, "{name}: value ABI");
        } else {
            assert!(map.value_size() > 0, "{name}: empty scratch value");
        }
        let flags = if map_type == BPF_MAP_TYPE_LPM_TRIE
            || map_type == BPF_MAP_TYPE_SK_STORAGE
        {
            1
        } else {
            0
        }; // BPF_F_NO_PREALLOC
        assert_eq!(map.map_flags(), flags, "{name}: flags");
        if map_type != BPF_MAP_TYPE_RINGBUF {
            assert_ne!(btf_map.def.btf_key_type_id, 0, "{name}: missing key type");
            assert_ne!(
                btf_map.def.btf_value_type_id, 0,
                "{name}: missing value type"
            );
        }
    }
}

#[test]
#[ignore = "requires freshly built eBPF bytecode and privileges to load BPF"]
fn btf_maps_and_programs_load_without_attaching() {
    assert!(!BYTECODE.is_empty(), "build clash-ebpf-bpf first");
    // Loading allocates temporary maps/programs. No hooks are attached and all
    // FDs are released when the test finishes, so live traffic is unaffected.
    let mut bpf = aya::EbpfLoader::new()
        .load(BYTECODE)
        .expect("create BTF maps");
    for (name, program) in bpf.programs_mut() {
        let result = match program {
            Program::SchedClassifier(program) => program.load(),
            Program::SkLookup(program) => program.load(),
            Program::CgroupSock(program) => program.load(),
            Program::CgroupSockAddr(program) => program.load(),
            _ => panic!("unexpected program type for {name}"),
        };
        result.unwrap_or_else(|error| panic!("load {name}: {error}"));
    }
}

#[test]
#[ignore = "requires root and writable cgroup2; run with --test-threads=1"]
fn cgroup_socket_identity_and_active_open_are_preserved() {
    use aya::{
        maps::{HashMap, SkStorage},
        programs::CgroupAttachMode,
    };
    use std::{
        fs,
        net::{TcpListener, TcpStream, UdpSocket},
        os::fd::AsRawFd,
        path::PathBuf,
    };

    // Attach only to a new, temporary cgroup containing this test process.
    // Restore membership before deleting the cgroup, including on panic.
    struct Membership {
        original: PathBuf,
        temporary: PathBuf,
        pid: String,
    }
    impl Drop for Membership {
        fn drop(&mut self) {
            fs::write(self.original.join("cgroup.procs"), &self.pid)
                .expect("restore test cgroup");
            fs::remove_dir(&self.temporary).expect("remove test cgroup");
        }
    }
    let current = fs::read_to_string("/proc/self/cgroup").unwrap();
    let relative = current
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap();
    let original =
        PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let temporary = PathBuf::from(format!(
        "/sys/fs/cgroup/clash-ebpf-opt-test-{}",
        std::process::id()
    ));
    fs::create_dir(&temporary).expect("create isolated cgroup");
    let membership = Membership {
        original,
        temporary,
        pid: std::process::id().to_string(),
    };
    let mut bpf = aya::EbpfLoader::new().load(BYTECODE).unwrap();
    let cgroup = fs::File::open(&membership.temporary).unwrap();
    for name in [
        "tproxy_wan_cg_sock_create",
        "tproxy_wan_cg_sock_release",
        "tproxy_wan_cg_connect4",
        "tproxy_wan_cg_sendmsg4",
    ] {
        match bpf.program_mut(name).unwrap() {
            Program::CgroupSock(p) => {
                p.load().unwrap();
                p.attach(&cgroup, CgroupAttachMode::Single).unwrap();
            }
            Program::CgroupSockAddr(p) => {
                p.load().unwrap();
                p.attach(&cgroup, CgroupAttachMode::Single).unwrap();
            }
            _ => panic!("wrong program type"),
        }
    }
    fs::write(membership.temporary.join("cgroup.procs"), &membership.pid).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let policy =
        SkStorage::<_, u32>::try_from(bpf.map("TCP_SOCKET_POLICY").unwrap())
            .unwrap();
    assert_eq!(policy.get(&client, 0).unwrap(), 1);
    assert!(matches!(
        policy.get(&listener, 0),
        Err(aya::maps::MapError::KeyNotFound)
    ));
    assert!(matches!(
        policy.get(&server, 0),
        Err(aya::maps::MapError::KeyNotFound)
    ));

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.connect(listener.local_addr().unwrap()).unwrap();
    assert!(matches!(
        policy.get(&udp, 0),
        Err(aya::maps::MapError::KeyNotFound)
    ));
    let mut cookie = 0u64;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                udp.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut len,
            )
        },
        0
    );
    let identities =
        HashMap::<_, u64, PIDName>::try_from(bpf.map("COOKIE_PID_MAP").unwrap())
            .unwrap();
    let before = identities.get(&cookie, 0).unwrap();
    struct Comm([u8; 16]);
    impl Drop for Comm {
        fn drop(&mut self) {
            unsafe {
                libc::prctl(libc::PR_SET_NAME, self.0.as_ptr());
            }
        }
    }
    let mut comm = Comm([0; 16]);
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_NAME, comm.0.as_mut_ptr()) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NAME, c"ebpf-refresh".as_ptr()) },
        0
    );
    udp.send_to(b"refresh", listener.local_addr().unwrap()).unwrap();
    let refreshed = identities.get(&cookie, 0).unwrap();
    assert_eq!(refreshed.pid, before.pid);
    assert_eq!(&refreshed.pname[..12], b"ebpf-refresh");
    assert_ne!(refreshed.pname, before.pname);
}
