#[cfg(test)]
mod tests {

    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::hash::MessageDigest;
    use openssl::md::Md;
    use openssl::nid::Nid;
    use openssl::pkey::Id;
    use openssl::pkey_ctx::HkdfMode;
    use openssl::pkey_ctx::PkeyCtx;
    use std::ffi::CString;
    use std::ptr;
    use winapi::shared::winerror::{NTE_INVALID_HANDLE, NTE_INVALID_PARAMETER};
    use windows::core::{w, HRESULT, PCWSTR};
    use windows::Win32::Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
    use windows::Win32::Security::Cryptography::*;

    // Bob does ECDH using BCrypt then OpenSSL
    // Expect two method to produce same output
    // But couldn't find proper way to configure BCryptDeriveKey to mimic output of OpenSSL
    // Assume key size 256bit
    #[test]
    fn test_bcrypt_derive_other_mode() {
        // Bob generate ECC key pair
        let mut bob_private_key: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE::default();
        let mut alice_pub_key: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE::default();
        let mut bob_secret_handle = BCRYPT_SECRET_HANDLE::default();

        unsafe {
            let mut alg_provider = BCRYPT_ALG_HANDLE::default();
            let result = BCryptOpenAlgorithmProvider(
                &mut alg_provider,
                BCRYPT_ECDH_P256_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            );
            assert_eq!(result, NTSTATUS::default());

            // Bob ECC Key Creation
            let result =
                BCryptGenerateKeyPair(alg_provider, ptr::addr_of_mut!(bob_private_key), 256, 0);
            assert_eq!(result, STATUS_SUCCESS);

            let result = BCryptFinalizeKeyPair(bob_private_key, 0);
            assert_eq!(result, STATUS_SUCCESS);

            // Bob import Alice ECC Pub Key (created somewhere else)
            let alice_public_key_bcrypt: [u8; 72] = [
                69, 67, 75, 49, 32, 0, 0, 0, 181, 197, 131, 26, 83, 32, 94, 96, 176, 253, 26, 47,
                161, 57, 126, 85, 139, 136, 106, 142, 158, 134, 17, 215, 102, 217, 220, 227, 225,
                18, 249, 106, 2, 178, 245, 62, 188, 14, 25, 249, 119, 146, 18, 203, 225, 25, 180,
                27, 205, 202, 68, 152, 14, 80, 78, 225, 193, 78, 25, 176, 70, 235, 27, 76,
            ];

            // Bob import Alice pub key
            let result = BCryptImportKeyPair(
                alg_provider,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut alice_pub_key,
                &alice_public_key_bcrypt,
                0,
            );
            assert_eq!(result, STATUS_SUCCESS);

            // Bob do secret gen
            let result =
                BCryptSecretAgreement(bob_private_key, alice_pub_key, &mut bob_secret_handle, 0);
            assert_eq!(result, STATUS_SUCCESS);

            // Bob Export Secret so we can run OpenSSL Derive Key
            let mut bob_secret_blob = [0; 32];
            let mut bob_secret_blob_len = 0;
            let result = BCryptDeriveKey(
                bob_secret_handle,
                BCRYPT_KDF_RAW_SECRET,
                None,
                Some(&mut bob_secret_blob),
                &mut bob_secret_blob_len,
                0,
            );
            assert_eq!(result, STATUS_SUCCESS);

            /////////////////////
            /// Question here //
            /////////////////////

            // Bob derive key
            // How to use this properties? What does they mean? What value should they have?
            let mut param_buffers = [
                // Algorithm ID
                BCryptBuffer {
                    cbBuffer: 0 as u32,
                    BufferType: KDF_ALGORITHMID,
                    pvBuffer: std::ptr::null_mut(),
                },
                // Party U Info
                BCryptBuffer {
                    cbBuffer: 0 as u32,
                    BufferType: KDF_PARTYUINFO,
                    pvBuffer: std::ptr::null_mut(),
                },
                // Party V Info
                BCryptBuffer {
                    cbBuffer: 0 as u32,
                    BufferType: KDF_PARTYVINFO,
                    pvBuffer: std::ptr::null_mut(),
                },
            ];

            let param_list = BCryptBufferDesc {
                ulVersion: BCRYPTBUFFER_VERSION,
                cBuffers: param_buffers.len() as u32,
                pBuffers: param_buffers.as_mut_ptr() as *mut BCryptBuffer,
            };

            let mut output_size = 0u32;
            let result = BCryptDeriveKey(
                bob_secret_handle,
                BCRYPT_KDF_SP80056A_CONCAT,
                Some(&param_list),
                None,
                &mut output_size,
                0,
            );
            assert_eq!(result, STATUS_SUCCESS);
            println!("Required output_size: {:?}", output_size);

            let mut derived_key_bcrypt = [0u8; 32];
            let result = BCryptDeriveKey(
                bob_secret_handle,
                BCRYPT_KDF_SP80056A_CONCAT,
                Some(&param_list),
                Some(&mut derived_key_bcrypt),
                &mut output_size,
                0,
            );
            assert_eq!(result, STATUS_SUCCESS);
            // println!("derived_key_buf: {:?}", derived_key_bcrypt);

            // Key Derivation using OpenSSL (copied from our service)
            let mut derived_key_openssl = [0u8; 32];
            let mut ctx = PkeyCtx::new_id(Id::HKDF).unwrap();
            ctx.derive_init().unwrap();
            ctx.set_hkdf_key(&bob_secret_blob).unwrap();
            ctx.set_hkdf_md(&Md::sha256()).unwrap();
            ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND).unwrap();

            // How to have BCrypt produce the same output as this?
            ctx.derive(Some(&mut derived_key_openssl)).unwrap();

            assert_eq!(derived_key_openssl, derived_key_bcrypt);

            // TODO: Cleanup
        }
    }
}
