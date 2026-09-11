#![warn(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_long, c_void};
use core::marker::PhantomData;
use core::ptr;
use std::ffi::CStr;
use std::os::raw::c_int;
use std::slice;
use std::sync::LazyLock;

use openssl_sys::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_SSL_CTX, CRYPTO_get_ex_new_index, ERR_PACK, ERR_STRING_DATA,
    ERR_get_next_error_library, ERR_load_strings, ERR_new, ERR_set_debug, ERR_set_error,
    OPENSSL_free, OPENSSL_sk_num, OPENSSL_sk_value, SSL, SSL_CTX, SSL_CTX_get_ex_data,
    SSL_CTX_set_ex_data, SSL_get_SSL_CTX, SSL_get_ex_data_X509_STORE_CTX_idx, X509, X509_STORE_CTX,
    X509_STORE_CTX_get_error_depth, X509_STORE_CTX_get_ex_data, X509_STORE_CTX_get0_chain,
    X509_STORE_CTX_set_error, X509_V_ERR_APPLICATION_VERIFICATION, X509_V_ERR_CERT_REVOKED,
    i2d_X509, stack_st_X509,
};
use rustls_pki_types::CertificateDer;
use upki::ffi::{
    upki_certificate_der, upki_check_revocation, upki_config, upki_config_free, upki_config_new,
    upki_result,
};

/// Sets the upki config to use for connections based upon `ctx`.
///
/// `config` becomes owned by `SSL_CTX`.  If `config` is NULL the previous configuration is
/// freed.
///
/// # Thread safety
///
/// This inherits the property of the OpenSSL API, whereby a single `SSL_CTX` cannot be shared
/// between threads.
///
/// # Safety
///
/// This does nothing if `ctx` is NULL.  `config` is required to be a valid `upki_config` pointer,
/// or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_openssl_set_config(ctx: *mut SSL_CTX, config: *const upki_config) {
    if ctx.is_null() {
        return;
    }

    let Some(index) = *UPKI_SSL_CTX_CONFIG_INDEX else {
        return;
    };

    // SAFETY: `upki_config_free` is defined for a previous valid pointer, or NULL.
    // We also rely on `SSL_CTX_get_ex_data` only returning NULL or a previous
    // pointer provided to `SSL_CTX_set_ex_data`.
    unsafe {
        // free any previous value.
        upki_config_free(SSL_CTX_get_ex_data(ctx, index).cast());
    }

    // SAFETY: `ctx` is required to be non-NULL (as established above).
    unsafe {
        SSL_CTX_set_ex_data(ctx, index, config.cast_mut().cast());
    }
}

/// Checks certificate revocation using upki, matching OpenSSL's `SSL_verify_cb` interface.
///
/// This function returns 0 if called with 0 for the `preverify_ok` parameter.
/// As a result, it never allows a verification to pass if the previous verification
/// step has failed.
///
/// If the certificate chain obtained from `x509_ctx` is not included in the revocation data,
/// this function returns `preverify_ok`.
///
/// # Configuration
///
/// If ``upki_openssl_set_config()` was previously called against the `SSL_CTX` available
/// from `X509_STORE_CTX`, this configuration is used.
///
/// Otherwise, if that function wasn't called, or no `SSL_CTX` can be obtained from `X509_STORE_CTX`,
/// the configuration file and data location is found automatically based on defaults.
///
/// # Errors
///
/// If the certificate chain obtained from `x509_ctx` is revoked, this function returns 0
/// and sets the `X509_V_ERR_CERT_REVOKED` error on `x509_ctx` (using
/// `X509_STORE_CTX_set_error(3SSL)`).
///
/// If the revocation status cannot be determined, this function returns 0 and sets
/// the `X509_V_ERR_APPLICATION_VERIFICATION` error on `x509_ctx` (using
/// `X509_STORE_CTX_set_error(3SSL)`).
///
/// On unexpected/unrecoverable errors, this function returns 0 and may add a report
/// to the OpenSSL error stack giving more detail.
///
/// # Safety
///
/// This function requires that `x509_ctx` is a valid pointer, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_openssl_verify_callback(
    mut preverify_ok: c_int,
    x509_ctx: *mut X509_STORE_CTX,
) -> c_int {
    // Revocation checking never improves the situation if the verification has failed.
    if preverify_ok == 0 {
        return preverify_ok;
    }

    // SAFETY: We rely on the caller providing a valid or NULL `x509_ctx` pointer.  This
    // is required by the C undefined behavior rules (C17 §6.3.2.3 item 7)
    let Some(mut x509_ctx) = (unsafe { BorrowedX509StoreCtx::from_ptr(x509_ctx) }) else {
        return 0;
    };

    // This callback is called once per certificate, with the final call being for the
    // leaf certificate denoted by error_depth = 0.   We only process the chain as a whole;
    // do this at the leaf certificate level.
    if x509_ctx.error_depth() != 0 {
        return preverify_ok;
    }

    let Some(chain) = x509_ctx.chain() else {
        return 0;
    };

    let Some(certs) = chain.copy_certs() else {
        return 0;
    };

    let cert_descriptors = certs
        .iter()
        .map(BorrowedUpkiCertificateDer::from_cert)
        .collect::<Vec<BorrowedUpkiCertificateDer<'_>>>();

    if cert_descriptors.is_empty() {
        x509_ctx.set_error(X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }

    let config = match UpkiConfig::new(&x509_ctx) {
        Ok(config) => config,
        Err(e) => {
            x509_ctx.set_detailed_error(X509_V_ERR_APPLICATION_VERIFICATION, e, line!());
            return 0;
        }
    };

    // SAFETY: `upki_check_revocation` requires:
    // - a valid config pointer, established above (either transitively via the safety
    //   preconditions on `upki_openssl_set_config`, or by creating one stored in `_our_config`)
    // - valid pointers to a sequence of certificates, which is provided by the `cert_descriptors` vec.
    match unsafe {
        upki_check_revocation(
            config.as_ptr(),
            cert_descriptors.as_ptr().cast(),
            cert_descriptors.len(),
        )
    } {
        upki_result::UPKI_REVOCATION_REVOKED => {
            x509_ctx.set_error(X509_V_ERR_CERT_REVOKED);
            preverify_ok = 0;
        }
        upki_result::UPKI_REVOCATION_NOT_COVERED | upki_result::UPKI_REVOCATION_NOT_REVOKED => {}
        e => {
            x509_ctx.set_detailed_error(X509_V_ERR_APPLICATION_VERIFICATION, e, line!());
            preverify_ok = 0;
        }
    }

    preverify_ok
}

struct BorrowedX509StoreCtx<'a>(&'a mut X509_STORE_CTX);

impl<'a> BorrowedX509StoreCtx<'a> {
    unsafe fn from_ptr(ptr: *mut X509_STORE_CTX) -> Option<Self> {
        // SAFETY: we pass up the requirements of `ptr::as_mut()` to our caller
        unsafe { ptr.as_mut() }.map(Self)
    }

    fn error_depth(&self) -> c_int {
        // SAFETY: the input pointer is valid, because it comes from our reference.
        unsafe { X509_STORE_CTX_get_error_depth(ptr::from_ref(self.0)) }
    }

    fn chain(&self) -> Option<BorrowedX509Stack<'a>> {
        // SAFETY: This type guarantees that the pointer is of the correct type, alignment, etc,
        // and is non-NULL (via coming from a reference.)
        let chain = unsafe { X509_STORE_CTX_get0_chain(ptr::from_ref(self.0)) };

        // SAFETY: we require that openssl correctly returns a valid pointer, or NULL.
        unsafe { chain.as_ref() }.map(BorrowedX509Stack)
    }

    fn set_error(&mut self, err: i32) {
        // SAFETY: the input pointer is valid, because it comes from our reference.
        // OpenSSL does not document any other preconditions.
        unsafe { X509_STORE_CTX_set_error(ptr::from_mut(self.0), err) };
    }

    fn set_detailed_error(&mut self, verify_err: i32, upki_error: upki_result, calling_line: u32) {
        self.set_error(verify_err);

        // Lazy init library code, well outside any manipulation of the openssl error stack.
        let lib = *UPKI_ERR_LIB;

        // SAFETY: out of our hands (no parameters or return value)
        unsafe { ERR_new() };

        // SAFETY: file C-string is static, see its safety comment for argument that it is zero-terminated.
        unsafe { ERR_set_debug(THIS_FILE_CSTR.as_ptr(), calling_line as c_int, ptr::null()) };

        // SAFETY: format C-string is static, so cannot contain inappropriate specifiers.
        // single parameter is a further static C-string, as expected by %s.
        unsafe {
            ERR_set_error(
                lib,
                upki_error as c_int,
                c"%s".as_ptr(),
                UNEXPECTED_UPKI_ERROR.as_ptr(),
            )
        };
    }

    fn upki_config_from_ssl_ctx(&self) -> *const upki_config {
        let ssl_ctx = self.ssl_ctx();

        match (ssl_ctx.is_null(), *UPKI_SSL_CTX_CONFIG_INDEX) {
            // SAFETY: `ssl_ctx` is non-NULL, the index only has a upki_config pointer inserted into it.
            (false, Some(index)) => unsafe { SSL_CTX_get_ex_data(ssl_ctx, index).cast() },
            (_, _) => ptr::null(),
        }
    }

    fn ssl_ctx(&self) -> *const SSL_CTX {
        // SAFETY: the input pointer is valid, because it comes from our reference.
        let ssl: *const SSL = unsafe {
            X509_STORE_CTX_get_ex_data(ptr::from_ref(self.0), SSL_get_ex_data_X509_STORE_CTX_idx())
                .cast()
        };

        match ssl.is_null() {
            true => ptr::null(),
            // SAFETY: `SSL_get_SSL_CTX` requires non-NULL parameter, established here.
            false => unsafe { SSL_get_SSL_CTX(ssl) },
        }
    }
}

struct BorrowedX509Stack<'a>(&'a stack_st_X509);

impl<'a> BorrowedX509Stack<'a> {
    fn copy_certs(&self) -> Option<Vec<CertificateDer<'static>>> {
        // SAFETY: the stack pointer is valid, thanks to it being from a reference.
        let count = unsafe { OPENSSL_sk_num(ptr::from_ref(self.0).cast()) };
        if count < 0 {
            return None;
        }

        let mut certs = vec![];
        for i in 0..count {
            // SAFETY: the stack pointer is valid, thanks to it being from a reference.  `OPENSSL_sk_value` returns
            // a valid pointer to the item or NULL.
            let x509: *const X509 =
                unsafe { OPENSSL_sk_value(ptr::from_ref(self.0).cast(), i).cast() };

            // SAFETY: we require OpenSSL only fills the stack with valid pointers to X509 objects (or NULL)
            let x509 = unsafe { x509.as_ref() }?;
            certs.push(x509_to_certificate_der(x509)?);
        }

        Some(certs)
    }
}

enum UpkiConfig {
    FromContext(*const upki_config),
    Owned(*mut upki_config),
}

impl UpkiConfig {
    fn new(store_ctx: &BorrowedX509StoreCtx<'_>) -> Result<Self, upki_result> {
        match store_ctx.upki_config_from_ssl_ctx() {
            ptr if !ptr.is_null() => {
                return Ok(Self::FromContext(ptr));
            }
            _ => {}
        };

        let mut ptr = ptr::null_mut();
        // SAFETY: `upki_config_new` requires a pointer output, as established here.
        let rc = unsafe { upki_config_new(ptr::null(), &mut ptr) };

        match ptr.is_null() {
            true => Err(rc),
            false => Ok(Self::Owned(ptr)),
        }
    }

    fn as_ptr(&self) -> *const upki_config {
        match self {
            Self::FromContext(ptr) => *ptr,
            Self::Owned(ptr) => *ptr,
        }
    }
}

impl Drop for UpkiConfig {
    fn drop(&mut self) {
        if let Self::Owned(ptr) = self {
            // SAFETY: `upki_config_free` defined for a valid pointer or NULL.
            unsafe { upki_config_free(*ptr) }
        }
    }
}

/// A `upki_certificate_der` with borrow information intact.
#[repr(transparent)]
struct BorrowedUpkiCertificateDer<'a>(upki_certificate_der, PhantomData<&'a ()>);

impl<'a> BorrowedUpkiCertificateDer<'a> {
    fn from_cert(a: &'a CertificateDer<'a>) -> Self {
        Self(
            upki_certificate_der {
                data: a.as_ptr(),
                len: a.len(),
            },
            PhantomData,
        )
    }
}

fn x509_to_certificate_der(x509: &'_ X509) -> Option<CertificateDer<'static>> {
    // SAFETY: the x509 pointer is valid, thanks to it coming from a reference.
    let (ptr, len) = unsafe {
        let mut ptr = ptr::null_mut();
        let len = i2d_X509(ptr::from_ref(x509), &mut ptr);
        (ptr, len)
    };

    if len <= 0 || ptr.is_null() {
        return None;
    }
    let len = len as usize;

    let mut v = Vec::with_capacity(len);
    // SAFETY: we rely on i2d_X509 allocating `ptr` correctly and signalling an error via negative `len` if not.
    // `ptr` must be an allocated pointer from OpenSSL's allocator.
    unsafe {
        v.extend_from_slice(slice::from_raw_parts(ptr, len));
        OPENSSL_free(ptr as *mut _);
    }
    Some(v.into())
}

static UPKI_SSL_CTX_CONFIG_INDEX: LazyLock<Option<c_int>> = LazyLock::new(|| unsafe {
    // SAFETY: no documented safety conditions for this function.
    let index = CRYPTO_get_ex_new_index(
        CRYPTO_EX_INDEX_SSL_CTX,
        0,
        ptr::null_mut(),
        None,
        None,
        Some(ssl_ctx_upki_config_free),
    );
    match index {
        -1 => None,
        _ => Some(index),
    }
});

/// Funnel `CRYPTO_EX_free` into calling `upki_config_free`.
unsafe extern "C" fn ssl_ctx_upki_config_free(
    _parent: *mut c_void,
    config: *mut c_void,
    _ad: *mut CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    // SAFETY: The previous value is either NULL or a valid config pointer.
    // This matches the precondition of `upki_config_free`.
    unsafe { upki_config_free(config.cast()) };
}

static UPKI_ERR_LIB: LazyLock<c_int> = LazyLock::new(|| {
    // SAFETY: no safety pre- or post-conditions. may return 0 on error.
    let lib = unsafe { ERR_get_next_error_library() };

    let mut error_strings = Vec::new();

    // library name reserves error 0.
    error_strings.push(ERR_STRING_DATA {
        error: ERR_PACK(lib, 0, 0),
        string: c"upki".as_ptr(),
    });

    for err in upki_result::ALL {
        if matches!(err, upki_result::UPKI_OK) {
            continue;
        }
        error_strings.push(ERR_STRING_DATA {
            error: ERR_PACK(lib, 0, *err as i32),
            string: err.c_str().as_ptr(),
        });
    }

    // terminator
    error_strings.push(ERR_STRING_DATA {
        error: 0,
        string: ptr::null(),
    });

    // SAFETY: `ERR_load_strings` mutates and retains provided pointer, so we
    // immediately leak it.
    unsafe {
        ERR_load_strings(lib, error_strings.as_mut_ptr());
        core::mem::forget(error_strings);
    };

    lib
});

// SAFETY: the parameter to `from_bytes_with_nul_unchecked` always contains a zero byte,
// thanks to the one added.  `file!()` cannot contain a zero byte in practice.
static THIS_FILE_CSTR: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(concat!(file!(), "\0").as_bytes()) };

static UNEXPECTED_UPKI_ERROR: &CStr = c"unexpected upki error";

#[cfg(test)]
mod test;
