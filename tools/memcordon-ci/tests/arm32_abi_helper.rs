use memcordon_ci::arm32_abi_helper::static_aarch32_helper;

#[test]
fn reviewed_helper_is_static_arm_eabi_with_getpid_as_first_syscall() {
    let image = static_aarch32_helper();
    assert_eq!(&image[..7], b"\x7fELF\x01\x01\x01");
    assert_eq!(u16::from_le_bytes(image[16..18].try_into().unwrap()), 2);
    assert_eq!(u16::from_le_bytes(image[18..20].try_into().unwrap()), 40);
    assert_eq!(
        u32::from_le_bytes(image[24..28].try_into().unwrap()),
        0x11000
    );
    assert_eq!(
        u32::from_le_bytes(image[36..40].try_into().unwrap()),
        0x0500_0000
    );
    assert_eq!(u16::from_le_bytes(image[44..46].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(image[52..56].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(image[56..60].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(image[76..80].try_into().unwrap()), 5);
    assert_eq!(&image[4096..4104], &[0x14, 0x70, 0xa0, 0xe3, 0, 0, 0, 0xef]);
    assert_eq!(image.len(), 4096 + 14 * 4);
}
