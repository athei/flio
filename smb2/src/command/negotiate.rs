enum SecurityMode: u16 {
    SigningEnabled = 0x01,
    SigningRequired = 0x02
}

enum Capabilities: u32 {
    DFS = 0x01,
    LEASING = 0x02,
    LARGE_MTU = 0x04,
    MULTI_CHANNEL = 0x08,
    PERSISTENT_HANDLES = 0x10,
    DIRECTORY_LEASING = 0x20,
    GLOBAL_CAP_ENCRYPTION = 0x40,
}

struct NegotiateRequest {

}