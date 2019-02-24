use bitflags::bitflags;
use num_derive::FromPrimitive;

#[derive(FromPrimitive)]
enum SecurityMode {
    SigningEnabled = 0x01,
    SigningRequired = 0x02
}

bitflags! {
    pub struct Capabilities: u32 {
        const DFS = 0x01;
        const LEASING = 0x02;
        const LARGE_MTU = 0x04;
        const MULTI_CHANNEL = 0x08;
        const PERSISTENT_HANDLES = 0x10;
        const DIRECTORY_LEASING = 0x20;
        const GLOBAL_CAP_ENCRYPTION = 0x40;
    }
}

pub struct NegotiateRequest {

}

pub struct NegotiateResponse {

}
