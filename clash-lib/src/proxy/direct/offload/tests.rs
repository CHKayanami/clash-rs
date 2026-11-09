use super::*;

fn control(size: u32) -> Vec<u8> {
    let mut words = [0usize; 8];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_control = words.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
    // SAFETY: aligned initialized storage has capacity for a header and u32.
    // The returned byte copy owns its storage and has no borrowed pointers.
    unsafe {
        let header = message.msg_control.cast::<libc::cmsghdr>();
        (*header).cmsg_len = libc::CMSG_LEN(4) as _;
        (*header).cmsg_level = libc::SOL_UDP;
        (*header).cmsg_type = libc::UDP_GRO;
        copy_nonoverlapping(size.to_ne_bytes().as_ptr(), libc::CMSG_DATA(header), 4);
        std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), message.msg_controllen as usize).to_vec()
    }
}

#[test]
fn udp_gro_control_rejects_truncation_duplicates_and_invalid_segment_sizes() {
    assert_eq!(gro_size(&[]).unwrap(), None);
    assert_eq!(gro_size(&control(1472)).unwrap(), NonZeroU16::new(1472));
    assert!(gro_size(&control(0)).is_err());
    assert!(gro_size(&control(65536)).is_err());
    let valid = control(1472);
    assert!(gro_size(&valid[..size_of::<libc::cmsghdr>() - 1]).is_err());
    let mut duplicate = valid.clone(); duplicate.extend_from_slice(&valid);
    assert!(gro_size(&duplicate).is_err());
}
