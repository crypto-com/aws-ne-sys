// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)

mod ffi;

pub enum Error {
    SdkInitError,
    SdkGenericError,
    SdkKmsConfigError,
    SdkKmsClientError,
    SdkKmsDecryptError,
}

/// KMS decrypt FFI wrapper
/// TODO: Add a trait for Drop wrappers for SDK resources
pub fn kms_decrypt(
    aws_region: &[u8],
    aws_key_id: &[u8],
    aws_secret_key: &[u8],
    aws_session_token: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Initialize the SDK
    unsafe {
        ffi::aws_nitro_enclaves_library_init(std::ptr::null_mut());
    };

    // Fetch allocator
    let allocator = unsafe { ffi::aws_nitro_enclaves_get_allocator() };
    if allocator.is_null() {
        unsafe {
            ffi::aws_nitro_enclaves_library_clean_up();
        }
        return Err(Error::SdkInitError);
    }
    // REGION
    let region = unsafe {
        let reg = ffi::aws_string_new_from_array(allocator, aws_region.as_ptr(), aws_region.len());
        if reg.is_null() {
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        reg
    };
    // ENDPOINT
    let mut endpoint = {
        let mut ep = ffi::aws_socket_endpoint {
            address: [0; ffi::AWS_ADDRESS_MAX_LEN],
            port: ffi::AWS_NE_VSOCK_PROXY_PORT,
        };
        ep.address[..ffi::AWS_NE_VSOCK_PROXY_ADDR.len()]
            .copy_from_slice(&ffi::AWS_NE_VSOCK_PROXY_ADDR);
        ep
    };
    // AWS_ACCESS_KEY_ID
    let key_id = unsafe {
        let kid = ffi::aws_string_new_from_array(allocator, aws_key_id.as_ptr(), aws_key_id.len());
        if kid.is_null() {
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        kid
    };
    // AWS_SECRET_ACCESS_KEY
    let secret_key = unsafe {
        let skey = ffi::aws_string_new_from_array(
            allocator,
            aws_secret_key.as_ptr(),
            aws_secret_key.len(),
        );
        if skey.is_null() {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        skey
    };
    // AWS_SESSION_TOKEN
    let session_token = unsafe {
        let sess_token = ffi::aws_string_new_from_array(
            allocator,
            aws_session_token.as_ptr(),
            aws_session_token.len(),
        );
        if sess_token.is_null() {
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        sess_token
    };
    // Construct KMS client configuration
    let kms_client_cfg = unsafe {
        // Configure
        let cfg = ffi::aws_nitro_enclaves_kms_client_config_default(
            region,
            &mut endpoint,
            ffi::AWS_SOCKET_VSOCK_DOMAIN,
            key_id,
            secret_key,
            session_token,
        );

        if cfg.is_null() {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkKmsConfigError);
        }
        cfg
    };
    // Construct KMS Client
    let kms_client = unsafe { ffi::aws_nitro_enclaves_kms_client_new(kms_client_cfg) };
    if kms_client.is_null() {
        unsafe {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
            ffi::aws_nitro_enclaves_library_clean_up();
        }
        return Err(Error::SdkKmsClientError);
    }
    // Ciphertext
    let ciphertext_buf = unsafe {
        ffi::aws_byte_buf_from_array(ciphertext.as_ptr() as *mut ffi::c_void, ciphertext.len())
    };

    // Decrypt
    let mut plaintext_buf: ffi::aws_byte_buf = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { ffi::aws_kms_decrypt_blocking(kms_client, &ciphertext_buf, &mut plaintext_buf) };
    if rc != 0 {
        unsafe {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
            ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
            ffi::aws_nitro_enclaves_library_clean_up();
        }
        return Err(Error::SdkKmsDecryptError);
    }

    // Cleanup
    unsafe {
        ffi::aws_string_destroy_secure(key_id);
        ffi::aws_string_destroy_secure(secret_key);
        ffi::aws_string_destroy_secure(session_token);
        ffi::aws_string_destroy_secure(region);
        ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
        ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
        ffi::aws_nitro_enclaves_library_clean_up();
    }

    // Plaintext
    let plaintext = unsafe {
        std::slice::from_raw_parts(plaintext_buf.buffer, plaintext_buf.len as usize).to_vec()
    };
    unsafe { ffi::aws_byte_buf_clean_up_secure(&mut plaintext_buf) };

    Ok(plaintext)
}

/// FFI wrapper to seed initial entropy using NSM
pub fn seed_entropy(bytes_to_seed: usize) -> Result<(), ()> {
    let rc = unsafe { ffi::aws_nitro_enclaves_library_seed_entropy(bytes_to_seed) };
    if rc == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// KMS encrypt FFI wrapper
/// TODO: Add a trait for Drop wrappers for SDK resources
pub fn kms_encrypt(
    aws_region: &[u8],
    aws_key_id: &[u8],
    aws_secret_key: &[u8],
    aws_session_token: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Initialize the SDK
    unsafe {
        ffi::aws_nitro_enclaves_library_init(std::ptr::null_mut());
    };

    // Fetch allocator
    let allocator = unsafe { ffi::aws_nitro_enclaves_get_allocator() };
    if allocator.is_null() {
        unsafe {
            ffi::aws_nitro_enclaves_library_clean_up();
        }
        return Err(Error::SdkInitError);
    }
    // REGION
    let region = unsafe {
        let reg = ffi::aws_string_new_from_array(allocator, aws_region.as_ptr(), aws_region.len());
        if reg.is_null() {
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        reg
    };
    // ENDPOINT
    let mut endpoint = {
        let mut ep = ffi::aws_socket_endpoint {
            address: [0; ffi::AWS_ADDRESS_MAX_LEN],
            port: ffi::AWS_NE_VSOCK_PROXY_PORT,
        };
        ep.address[..ffi::AWS_NE_VSOCK_PROXY_ADDR.len()]
            .copy_from_slice(&ffi::AWS_NE_VSOCK_PROXY_ADDR);
        ep
    };
    // AWS_ACCESS_KEY_ID
    let key_id = unsafe {
        let kid = ffi::aws_string_new_from_array(allocator, aws_key_id.as_ptr(), aws_key_id.len());
        if kid.is_null() {
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        kid
    };
    // AWS_SECRET_ACCESS_KEY
    let secret_key = unsafe {
        let skey = ffi::aws_string_new_from_array(
            allocator,
            aws_secret_key.as_ptr(),
            aws_secret_key.len(),
        );
        if skey.is_null() {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        skey
    };
    // AWS_SESSION_TOKEN
    let session_token = unsafe {
        let sess_token = ffi::aws_string_new_from_array(
            allocator,
            aws_session_token.as_ptr(),
            aws_session_token.len(),
        );
        if sess_token.is_null() {
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkGenericError);
        }
        sess_token
    };
    // Construct KMS client configuration
    let kms_client_cfg = unsafe {
        // Configure
        let cfg = ffi::aws_nitro_enclaves_kms_client_config_default(
            region,
            &mut endpoint,
            ffi::AWS_SOCKET_VSOCK_DOMAIN,
            key_id,
            secret_key,
            session_token,
        );

        if cfg.is_null() {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_library_clean_up();
            return Err(Error::SdkKmsConfigError);
        }
        cfg
    };
    // Construct KMS Client
    let kms_client = unsafe { ffi::aws_nitro_enclaves_kms_client_new(kms_client_cfg) };
    if kms_client.is_null() {
        unsafe {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
            ffi::aws_nitro_enclaves_library_clean_up();
        }
        return Err(Error::SdkKmsClientError);
    }
    // Plaintext
    let plaintext_buf = unsafe {
        ffi::aws_byte_buf_from_array(plaintext.as_ptr() as *mut ffi::c_void, plaintext.len())
    };

    // Encrypt
    let mut ciphertext_buf: ffi::aws_byte_buf = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { ffi::aws_kms_encrypt_blocking(kms_client, &plaintext_buf, &mut ciphertext_buf) };
    if rc != 0 {
        unsafe {
            ffi::aws_string_destroy_secure(key_id);
            ffi::aws_string_destroy_secure(secret_key);
            ffi::aws_string_destroy_secure(session_token);
            ffi::aws_string_destroy_secure(region);
            ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
            ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
            ffi::aws_nitro_enclaves_library_clean_up();
        }
        return Err(Error::SdkKmsDecryptError);
    }

    // Cleanup
    unsafe {
        ffi::aws_string_destroy_secure(key_id);
        ffi::aws_string_destroy_secure(secret_key);
        ffi::aws_string_destroy_secure(session_token);
        ffi::aws_string_destroy_secure(region);
        ffi::aws_nitro_enclaves_kms_client_config_destroy(kms_client_cfg);
        ffi::aws_nitro_enclaves_kms_client_destroy(kms_client);
        ffi::aws_nitro_enclaves_library_clean_up();
    }

    // Ciphertext
    let ciphertext = unsafe {
        std::slice::from_raw_parts(ciphertext_buf.buffer, ciphertext_buf.len as usize).to_vec()
    };
    unsafe { ffi::aws_byte_buf_clean_up_secure(&mut ciphertext_buf) };

    Ok(ciphertext)
}
