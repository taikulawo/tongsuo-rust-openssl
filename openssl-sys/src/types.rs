use libc::*;
use *;

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        pub type EVP_PKEY = evp_pkey_st;
        pub enum evp_pkey_st {}
    } else {
        #[repr(C)]
        pub struct EVP_PKEY {
            pub type_: c_int,
            pub save_type: c_int,
            pub references: c_int,
            pub ameth: *const EVP_PKEY_ASN1_METHOD,
            pub engine: *mut ENGINE,
            pub pkey: *mut c_void,
            pub save_parameters: c_int,
            pub attributes: *mut stack_st_X509_ATTRIBUTE,
        }
    }
}
