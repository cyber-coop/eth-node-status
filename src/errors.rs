use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub enum Errors {
    UnreachableNode(NodeId),
    Disconnect(NodeId, u8),
    EIP8Error(NodeId),
    TimeOut(NodeId),
    UnreadablePayload(NodeId, Vec<u8>),
    UnknownError(NodeId),
}

#[derive(Debug, Clone)]
pub struct NodeId(Vec<u8>, String, i32);

impl NodeId {
    pub fn new(id: &Vec<u8>, address: &str, port: i32) -> NodeId {
        NodeId(id.clone(), address.to_string(), port)
    }

    pub fn id(&self) -> Vec<u8> {
        self.0.clone()
    }
}


impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Errors::UnreachableNode(node_id) =>
                write!(f, "[{}@{}:{}] Unreachable node", hex::encode(&node_id.0), node_id.1, node_id.2),
            Errors::Disconnect(node_id, reason) =>
                write!(f, "[{}@{}:{}] node disconnected (reason {})", hex::encode(&node_id.0), node_id.1, node_id.2, reason),
            Errors::EIP8Error(node_id) =>
                write!(f, "[{}@{}:{}] EIP8 error", hex::encode(&node_id.0), node_id.1, node_id.2),
            Errors::TimeOut(node_id) =>
                write!(f, "[{}@{}:{}] Time Out error", hex::encode(&node_id.0), node_id.1, node_id.2),
            Errors::UnreadablePayload(node_id, payload) =>
                write!(f, "[{}@{}:{}] Couldn't read payload {}", hex::encode(&node_id.0), node_id.1, node_id.2, hex::encode(payload)),
            Errors::UnknownError(node_id) =>
                write!(f, "[{}@{}:{}] Unknown error", hex::encode(&node_id.0), node_id.1, node_id.2),
        }
    }
}

impl Error for Errors { }