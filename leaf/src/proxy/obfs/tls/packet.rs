#[derive(Copy, Clone)]
#[repr(C, align(1))]
pub struct tls_client_hello(pub tls_client_hello_Inner);
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct tls_client_hello_Inner {
    pub content_type: u8,
    pub version: u16,
    pub len: u16,
    pub handshake_type: u8,
    pub handshake_len_1: u8,
    pub handshake_len_2: u16,
    pub handshake_version: u16,
    pub random_unix_time: u32,
    pub random_bytes: [u8; 28],
    pub session_id_len: u8,
    pub session_id: [u8; 32],
    pub cipher_suites_len: u16,
    pub cipher_suites: [u8; 56],
    pub comp_methods_len: u8,
    pub comp_methods: [u8; 1],
    pub ext_len: u16,
}
#[allow(dead_code, non_upper_case_globals)]
const tls_client_hello_PADDING: usize =
    ::std::mem::size_of::<tls_client_hello>() - ::std::mem::size_of::<tls_client_hello_Inner>();

#[derive(Copy, Clone)]
#[repr(C, align(1))]
pub struct tls_ext_server_name(pub tls_ext_server_name_Inner);
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct tls_ext_server_name_Inner {
    pub ext_type: u16,
    pub ext_len: u16,
    pub server_name_list_len: u16,
    pub server_name_type: u8,
    pub server_name_len: u16,
}
#[allow(dead_code, non_upper_case_globals)]
const tls_ext_server_name_PADDING: usize = ::std::mem::size_of::<tls_ext_server_name>()
    - ::std::mem::size_of::<tls_ext_server_name_Inner>();

#[derive(Copy, Clone)]
#[repr(C, align(1))]
pub struct tls_ext_session_ticket(pub tls_ext_session_ticket_Inner);
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct tls_ext_session_ticket_Inner {
    pub session_ticket_type: u16,
    pub session_ticket_ext_len: u16,
}
#[allow(dead_code, non_upper_case_globals)]
const tls_ext_session_ticket_PADDING: usize = ::std::mem::size_of::<tls_ext_session_ticket>()
    - ::std::mem::size_of::<tls_ext_session_ticket_Inner>();

#[derive(Copy, Clone)]
#[repr(C, align(1))]
pub struct tls_ext_others(pub tls_ext_others_Inner);
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct tls_ext_others_Inner {
    pub ec_point_formats_ext_type: u16,
    pub ec_point_formats_ext_len: u16,
    pub ec_point_formats_len: u8,
    pub ec_point_formats: [u8; 3],
    pub elliptic_curves_type: u16,
    pub elliptic_curves_ext_len: u16,
    pub elliptic_curves_len: u16,
    pub elliptic_curves: [u8; 8],
    pub sig_algos_type: u16,
    pub sig_algos_ext_len: u16,
    pub sig_algos_len: u16,
    pub sig_algos: [u8; 30],
    pub encrypt_then_mac_type: u16,
    pub encrypt_then_mac_ext_len: u16,
    pub extended_master_secret_type: u16,
    pub extended_master_secret_ext_len: u16,
}
#[allow(dead_code, non_upper_case_globals)]
const tls_ext_others_PADDING: usize =
    ::std::mem::size_of::<tls_ext_others>() - ::std::mem::size_of::<tls_ext_others_Inner>();
