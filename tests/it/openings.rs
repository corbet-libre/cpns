//! Device protocol vectors and adversarial opening checks.

use cpns::{
    Fingerprint, FingerprintContext, Salt, SaltError, check_opening, check_opening_v2, fingerprint,
    fingerprint_v2,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn rejects_wrong_value_salt_and_each_corrupted_digest_byte() {
    let salt = Salt::from_bytes(vec![17; 16]).unwrap();
    let fp = fingerprint(b"restricted value", &salt);
    assert!(check_opening(&fp, b"restricted value", &salt));
    assert!(!check_opening(&fp, b"other value", &salt));
    let other = Salt::from_bytes(vec![18; 16]).unwrap();
    assert!(!check_opening(&fp, b"restricted value", &other));
    for index in 0..32 {
        let mut corrupt = *fp.as_bytes();
        corrupt[index] ^= 1;
        assert!(!check_opening(
            &Fingerprint::from_bytes(corrupt),
            b"restricted value",
            &salt
        ));
    }
}

#[test]
fn enforces_salt_length_and_accepts_binary_and_empty_values() {
    for length in 0..16 {
        assert_eq!(
            Salt::from_bytes(vec![0; length]).unwrap_err(),
            SaltError::TooShort
        );
    }
    for length in [16, 17, 32, 64, 1024] {
        let salt = Salt::from_bytes(vec![0xff; length]).unwrap();
        for value in [&b""[..], &b"\0\xff\x80\0"[..], "é🦀".as_bytes()] {
            assert!(check_opening(&fingerprint(value, &salt), value, &salt));
        }
    }
}

#[test]
fn framing_separates_identical_raw_concatenations() {
    let salt_a = Salt::from_bytes(vec![b'b'; 17]).unwrap();
    let salt_b = Salt::from_bytes(vec![b'b'; 16]).unwrap();
    assert_ne!(fingerprint(b"a", &salt_a), fingerprint(b"ab", &salt_b));
}

#[test]
fn canonical_bytes_are_not_silently_normalized() {
    let salt = Salt::from_bytes(vec![3; 32]).unwrap();
    assert_ne!(
        fingerprint("é".as_bytes(), &salt),
        fingerprint("e\u{301}".as_bytes(), &salt)
    );
    assert_ne!(fingerprint(b"1", &salt), fingerprint(b"01", &salt));
}

#[test]
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm"))]
fn fresh_salts_hide_a_return_to_an_old_value() {
    let first = Salt::generate().unwrap();
    let second = Salt::generate().unwrap();
    let third = Salt::generate().unwrap();
    assert_eq!(first.as_bytes().len(), 32);
    assert_ne!(first.as_bytes(), third.as_bytes());
    let initial = fingerprint(b"original", &first);
    let changed = fingerprint(b"changed", &second);
    let reverted = fingerprint(b"original", &third);
    assert_ne!(initial, changed);
    assert_ne!(initial, reverted);
    assert_ne!(changed, reverted);
    assert!(!check_opening(&reverted, b"original", &first));
}

#[test]
fn diagnostics_do_not_expose_openings_or_digests() {
    let salt = Salt::from_bytes(b"never print this salt".to_vec()).unwrap();
    assert_eq!(format!("{salt:?}"), "Salt([REDACTED])");
    assert_eq!(
        format!("{:?}", fingerprint(b"private", &salt)),
        "Fingerprint([REDACTED])"
    );
}

// Frozen vectors independently calculated with Python hashlib (OpenSSL SHA-256).
#[test]
fn matches_independent_v1_vectors() {
    {
        let value = [];
        let salt = Salt::from_bytes((0..16).collect()).unwrap();
        let expected = [
            62, 220, 135, 4, 173, 246, 65, 19, 4, 6, 69, 100, 142, 5, 27, 1, 131, 105, 60, 237,
            225, 134, 48, 209, 104, 229, 236, 0, 33, 1, 166, 212,
        ];
        assert_eq!(*fingerprint(&value, &salt).as_bytes(), expected);
    }
    {
        let value = [0, 255, 128];
        let salt = Salt::from_bytes((0..32).collect()).unwrap();
        let expected = [
            5, 212, 225, 80, 9, 78, 123, 67, 1, 86, 222, 79, 89, 253, 91, 96, 164, 153, 136, 139,
            90, 245, 146, 185, 16, 235, 135, 21, 210, 245, 0, 105,
        ];
        assert_eq!(*fingerprint(&value, &salt).as_bytes(), expected);
    }
    {
        let value = [104, 195, 169, 108, 108, 111, 240, 159, 166, 128];
        let salt = Salt::from_bytes((0..16).collect()).unwrap();
        let expected = [
            222, 100, 34, 105, 198, 219, 31, 242, 114, 235, 108, 76, 202, 248, 37, 37, 186, 173,
            205, 41, 252, 111, 94, 103, 70, 232, 233, 68, 55, 12, 177, 40,
        ];
        assert_eq!(*fingerprint(&value, &salt).as_bytes(), expected);
    }
}

#[test]
fn v2_requires_the_exact_context_value_salt_and_digest() {
    let context = FingerprintContext {
        community: "community",
        member: "member",
        field: "field",
    };
    let salt = Salt::from_bytes(vec![17; 16]).unwrap();
    let other_salt = Salt::from_bytes(vec![18; 16]).unwrap();
    let value = b"restricted value";
    let fp = fingerprint_v2(&context, value, &salt);
    assert!(check_opening_v2(&fp, &context, value, &salt));
    for other in [
        FingerprintContext {
            community: "other",
            ..context
        },
        FingerprintContext {
            member: "other",
            ..context
        },
        FingerprintContext {
            field: "other",
            ..context
        },
    ] {
        assert!(!check_opening_v2(&fp, &other, value, &salt));
    }
    assert!(!check_opening_v2(&fp, &context, b"wrong", &salt));
    assert!(!check_opening_v2(&fp, &context, value, &other_salt));
    for index in 0..32 {
        let mut corrupt = *fp.as_bytes();
        corrupt[index] ^= 1;
        assert!(!check_opening_v2(
            &Fingerprint::from_bytes(corrupt),
            &context,
            value,
            &salt
        ));
    }
    // Version selection is explicit in both directions, never a fallback.
    assert!(!check_opening(&fp, value, &salt));
    assert!(!check_opening_v2(
        &fingerprint(value, &salt),
        &context,
        value,
        &salt
    ));
}

#[test]
fn v2_frames_every_component_and_preserves_canonical_bytes() {
    let salt = Salt::from_bytes(vec![b'b'; 16]).unwrap();
    let a = FingerprintContext {
        community: "a",
        member: "bc",
        field: "d",
    };
    // Each pair has identical unframed concatenated bytes across a boundary.
    for b in [
        FingerprintContext {
            community: "ab",
            member: "c",
            ..a
        },
        FingerprintContext {
            member: "b",
            field: "cd",
            ..a
        },
    ] {
        assert_ne!(
            fingerprint_v2(&a, b"value", &salt),
            fingerprint_v2(&b, b"value", &salt)
        );
    }
    assert_ne!(
        fingerprint_v2(&a, b"evalue", &salt),
        fingerprint_v2(&FingerprintContext { field: "de", ..a }, b"value", &salt)
    );
    assert_ne!(
        fingerprint_v2(&a, b"valueb", &salt),
        fingerprint_v2(&a, b"value", &Salt::from_bytes(vec![b'b'; 17]).unwrap())
    );
    assert_ne!(
        fingerprint_v2(&FingerprintContext { field: "é", ..a }, b"", &salt),
        fingerprint_v2(
            &FingerprintContext {
                field: "e\u{301}",
                ..a
            },
            b"",
            &salt
        )
    );
    for length in [16, 17, 32, 64, 1024] {
        let salt = Salt::from_bytes(vec![0xff; length]).unwrap();
        for value in [&b""[..], &b"\0\xff\x80\0"[..], "é🦀".as_bytes()] {
            let fp = fingerprint_v2(&a, value, &salt);
            assert!(check_opening_v2(&fp, &a, value, &salt));
        }
    }
}

// Frozen vectors independently calculated with Python hashlib (OpenSSL SHA-256).
#[test]
fn matches_independent_v2_vectors() {
    let context = FingerprintContext {
        community: "community",
        member: "member",
        field: "field",
    };
    let salt = Salt::from_bytes((0..16).collect()).unwrap();
    let expected = [
        24, 187, 116, 195, 122, 182, 248, 238, 41, 164, 205, 137, 159, 138, 17, 171, 62, 44, 248,
        104, 23, 233, 139, 156, 179, 161, 65, 192, 250, 83, 139, 81,
    ];
    assert_eq!(*fingerprint_v2(&context, b"", &salt).as_bytes(), expected);
    let context = FingerprintContext {
        community: "社区",
        member: "é🦀",
        field: "f\0x",
    };
    let salt = Salt::from_bytes((0..32).collect()).unwrap();
    let expected = [
        218, 182, 102, 121, 3, 8, 153, 193, 200, 218, 21, 126, 83, 208, 127, 196, 121, 221, 193,
        112, 134, 229, 248, 135, 233, 184, 201, 24, 48, 183, 250, 115,
    ];
    assert_eq!(
        *fingerprint_v2(&context, &[0, 255, 128], &salt).as_bytes(),
        expected
    );
}
