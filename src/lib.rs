#[macro_use]
extern crate serde_derive;

pub static SOCKET_PATH: &str = "/run/usnetd.socket";

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ClientMessageIp {
    Ipv4(String),
    Ipv6(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    RequestNetmapPipe(String, u64),
    RequestUDS(String, u64),
    DeleteClient,
    AddMatch(WantMsg),
    RemoveMatch(WantMsg),
    QueryUsedPorts,
    QueryUsedPortsAnswer {
        listening: Vec<(u8, ClientMessageIp, u16)>,
        connected: Vec<(u8, ClientMessageIp, u16)>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WantMsg {
    pub dst_addr: ClientMessageIp,
    pub dst_port: Option<u16>,
    pub src_addr: Option<ClientMessageIp>,
    pub src_port: Option<u16>,
    pub protocol: u8,
}
