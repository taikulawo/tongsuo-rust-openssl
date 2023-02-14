use crate::{cvt, error::ErrorStack};
use std::{
    ffi::{c_int, CString},
    mem,
    path::Path,
};

use super::{ClientHelloResponse, SslContextBuilder, SslFiletype, SslMethod, SslRef};
use crate::{pkey, x509::X509};
use ffi::NTLS_method;
use foreign_types::{ForeignType, ForeignTypeRef};
#[cfg(ossl111)]
impl ClientHelloResponse {
    pub const ERROR: ClientHelloResponse = ClientHelloResponse(ffi::SSL_CLIENT_HELLO_ERROR);
}

impl SslContextBuilder {
    pub fn use_ntls_key_content_and_cert_content_pem(
        &mut self,
        sign_private_key_content: &[u8],
        sign_cert_content: &[u8],
        enc_private_key_content: &[u8],
        enc_cert_content: &[u8],
    ) -> Result<(), ErrorStack> {
        let sign_pkey = pkey::PKey::private_key_from_pem(sign_private_key_content)?;
        let sign_cert = X509::from_pem(sign_cert_content)?;
        let enc_pkey = pkey::PKey::private_key_from_pem(enc_private_key_content)?;
        let enc_cert = X509::from_pem(enc_cert_content)?;
        unsafe {
            cvt(ffi::SSL_CTX_use_sign_PrivateKey(
                self.as_ptr(),
                sign_pkey.as_ptr(),
            ))?;
            cvt(ffi::SSL_CTX_use_sign_certificate(
                self.as_ptr(),
                sign_cert.as_ptr(),
            ))?;
            cvt(ffi::SSL_CTX_use_enc_PrivateKey(
                self.as_ptr(),
                enc_pkey.as_ptr(),
            ))?;
            cvt(ffi::SSL_CTX_use_enc_certificate(
                self.as_ptr(),
                enc_cert.as_ptr(),
            ))?;
        };

        Ok(())
    }
}

impl SslRef {
    /// 只能在client hello callback中调用
    pub fn get_client_cipher_list_name(&mut self) -> Vec<String> {
        use std::{ffi::CStr, ptr, slice};

        let mut lists = vec![];
        unsafe {
            let mut ptr = ptr::null();
            let tmp: *mut *const _ = &mut ptr;
            let len = ffi::SSL_client_hello_get0_ciphers(self.as_ptr(), tmp as *mut _);
            let ciphers = slice::from_raw_parts::<u16>(ptr, len);
            for index in ciphers {
                let c = ffi::SSL_CIPHER_find(self.as_ptr(), index as *const _ as *const _);
                let name = ffi::SSL_CIPHER_get_name(c);
                let s = CStr::from_ptr(name).to_str().unwrap().to_string();
                lists.push(s);
            }
            lists
        }
    }
    pub fn disable_ntls(&mut self) {
        unsafe {
            ffi::SSL_disable_ntls(self.as_ptr());
        }
    }
    pub fn enable_ntls(&mut self) {
        unsafe {
            ffi::SSL_enable_ntls(self.as_ptr());
        }
    }
    pub fn use_ntls_key_content_and_cert_content_pem(
        &mut self,
        sign_private_key_content: &[u8],
        sign_cert_content: &[u8],
        enc_private_key_content: &[u8],
        enc_cert_content: &[u8],
    ) -> Result<(), ErrorStack> {
        let sign_pkey = pkey::PKey::private_key_from_pem(sign_private_key_content)?;
        let sign_cert = X509::from_pem(sign_cert_content)?;
        let enc_pkey = pkey::PKey::private_key_from_pem(enc_private_key_content)?;
        let enc_cert = X509::from_pem(enc_cert_content)?;
        // the following api take ownership from its args
        // mem::forget to transfer ownership
        unsafe {
            cvt(ffi::SSL_use_sign_PrivateKey(
                self.as_ptr(),
                sign_pkey.as_ptr(),
            ))?;
            cvt(ffi::SSL_use_sign_certificate(
                self.as_ptr(),
                sign_cert.as_ptr(),
            ))?;
            cvt(ffi::SSL_use_enc_PrivateKey(
                self.as_ptr(),
                enc_pkey.as_ptr(),
            ))?;
            cvt(ffi::SSL_use_enc_certificate(
                self.as_ptr(),
                enc_cert.as_ptr(),
            ))?;
            mem::forget(enc_cert);
        };

        Ok(())
    }
    pub fn use_ntls_key_and_cert<P: AsRef<Path>>(
        &mut self,
        sign_private_key_file: P,
        sign_cert_file: P,
        enc_private_key_file: P,
        enc_cert_file: P,
    ) -> Result<(), ErrorStack> {
        let sign_key =
            CString::new(sign_private_key_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        let sign_certificate =
            CString::new(sign_cert_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        let enc_key =
            CString::new(enc_private_key_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        let enc_certificate =
            CString::new(enc_cert_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_use_sign_PrivateKey_file(
                self.as_ptr(),
                sign_key.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ))?;
            cvt(ffi::SSL_use_sign_certificate_file(
                self.as_ptr(),
                sign_certificate.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ))?;
            cvt(ffi::SSL_use_enc_PrivateKey_file(
                self.as_ptr(),
                enc_key.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ))?;
            cvt(ffi::SSL_use_enc_certificate_file(
                self.as_ptr(),
                enc_certificate.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ))?;
        }
        Ok(())
    }
}

impl SslContextBuilder {
    pub fn enable_ntls(&mut self) {
        unsafe {
            ffi::SSL_CTX_enable_ntls(self.as_ptr());
        }
    }
}

impl SslMethod {
    pub fn ntls() -> SslMethod {
        unsafe { SslMethod(NTLS_method()) }
    }
}

pub const NID_SM2: c_int = 1172;
pub const SN_SM2: &str = "SM2";

// 铜锁API
impl pkey::PKey<pkey::Private> {
    #[cfg(feature = "tongsuo")]
    pub fn set_alias_type(&mut self, ty: c_int) {
        unsafe {
            ffi::EVP_PKEY_set_alias_type(self.as_ptr(), ty);
        }
    }
}
