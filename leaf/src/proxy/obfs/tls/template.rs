use super::packet;

pub const CLIENT_HELLO: packet::tls_client_hello =
    packet::tls_client_hello(packet::tls_client_hello_Inner {
        content_type: 0x16,
        version: 0x0301u16.to_be(),
        len: 0,

        handshake_type: 1,
        handshake_len_1: 0,
        handshake_len_2: 0,
        handshake_version: 0x0303u16.to_be(),

        random_unix_time: 0,
        random_bytes: [0; 28],

        session_id_len: 32,
        session_id: [0; 32],

        cipher_suites_len: 56u16.to_be(),
        cipher_suites: [
            0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b,
            0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27,
            0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
            0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
        ],

        comp_methods_len: 1,
        comp_methods: [0],

        ext_len: 0,
    });

pub const EXT_SERVER_NAME: packet::tls_ext_server_name =
    packet::tls_ext_server_name(packet::tls_ext_server_name_Inner {
        ext_type: 0,
        ext_len: 0,
        server_name_list_len: 0,
        server_name_type: 0,
        server_name_len: 0,
    });

pub const EXT_SESSION_TICKET: packet::tls_ext_session_ticket =
    packet::tls_ext_session_ticket(packet::tls_ext_session_ticket_Inner {
        session_ticket_type: 0x0023u16.to_be(),
        session_ticket_ext_len: 0,
    });

pub const EXT_OTHERS: packet::tls_ext_others =
    packet::tls_ext_others(packet::tls_ext_others_Inner {
        ec_point_formats_ext_type: 0x000Bu16.to_be(),
        ec_point_formats_ext_len: 4u16.to_be(),
        ec_point_formats_len: 3,
        ec_point_formats: [0x01, 0x00, 0x02],

        elliptic_curves_type: 0x000au16.to_be(),
        elliptic_curves_ext_len: 10u16.to_be(),
        elliptic_curves_len: 8u16.to_be(),
        elliptic_curves: [0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18],

        sig_algos_type: 0x000du16.to_be(),
        sig_algos_ext_len: 32u16.to_be(),
        sig_algos_len: 30u16.to_be(),
        sig_algos: [
            0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01,
            0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02,
            0x02, 0x03,
        ],

        encrypt_then_mac_type: 0x0016u16.to_be(),
        encrypt_then_mac_ext_len: 0,

        extended_master_secret_type: 0x0017u16.to_be(),
        extended_master_secret_ext_len: 0,
    });
