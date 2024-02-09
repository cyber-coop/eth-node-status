use std::{net::TcpStream, time::Duration};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::prelude::*;
use std::net::SocketAddr;
use std::collections::HashMap;
use rayon::prelude::*;

pub mod utils;
pub mod mac;
pub mod message;
pub mod types;
pub mod errors;
pub mod config;

use crate::{errors::{Errors, NodeId}, types::CapabilityMessage};

struct NodeInfo {
    remote_id: Vec<u8>,
    network_id: u64,
    capabilities: String,
}

fn main() {
    println!("Start getting status from nodes");
    let cfg = config::read_config();

    /******************
     * 
     *  Connect to postgres
     * 
     ******************/
     let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host,
        cfg.database.user,
        cfg.database.password,
        cfg.database.dbname,
    );

    let mut postgres_client = postgres::Client::connect(&database_params, postgres::NoTls).unwrap();

    let records = postgres_client.query("SELECT * FROM discv4.nodes WHERE network_id IS NULL;", &[]).unwrap();


    let mut trieur: HashMap<u64, u32> = HashMap::new();
    let mut disconnect_counter = 0;
    let mut eip8_error_counter = 0;
    let mut timeout_counter = 0;
    let mut unreadable_payload_counter = 0;

    let result: Vec<Result<NodeInfo, Errors>> = records.par_iter().map(|record| {
        let ip: String = record.get(0);
        let port: i32 = record.get(1);
        let remote_id: Vec<u8> = record.get(3);

        /******************
         * 
         *  Connect to node
         * 
         ******************/
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10));

        if stream.is_err() {
            println!("[{}@{}:{}] Couldn't reach node", hex::encode(&remote_id), ip, port);

            return Err(Errors::UnreachableNode(NodeId::new(&remote_id, &ip, port)));
        }

        let mut stream = stream.unwrap();
        // Set read timeout
        stream.set_read_timeout(Some(Duration::from_millis(5000))).unwrap();

        let private_key = hex::decode("472D4B6150645267556B58703273357638792F423F4528482B4D625165546856").unwrap();
        // Should be generated randomly
        let nonce = hex::decode("09267e7d55aada87e46468b2838cc616f084394d6d600714b58ad7a3a2c0c870").unwrap();
        // Epheremal private key (should be random)
        let ephemeral_privkey = hex::decode("691bb7a2fd6647eae78a235b9d305d09f796fe8e8ce7a18aa1aa1deff9649a02").unwrap();
        // Pad (should be generated randomly)
        let pad = hex::decode("eb035e803db3b2dea4a2c724739e7edaecb14ef242f5f4df58386b10626ab4887cc84d9dea153f24526200f4089946f4c4b26c283ac7e923e0c53dd1de83682df2fe44f4fe841c480465b38533e30c373ccb0022b95d722d577828862c9fe7e87e5e730bdecd4f358c7673e0999a06190f03e6d0ca98dae5aae8f16ca81c92").unwrap();
    
        /******************
         * 
        *  Create Auth message (EIP8 supported)
        * 
        ******************/
        println!("[{}@{}:{}] Creating EIP8 Auth message", hex::encode(&remote_id), ip, port);
        let init_msg = utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

        // send the message
        println!("[{}@{}:{}] Sending EIP8 Auth message", hex::encode(&remote_id), ip, port);
        stream.write(&init_msg).unwrap();
        stream.flush().unwrap();
    
        println!("[{}@{}:{}] waiting for answer...", hex::encode(&remote_id), ip, port);

        let mut buf = [0u8; 2];
        let _size = stream.read(&mut buf);
        
        let size_expected = buf.as_slice().read_u16::<BigEndian>().unwrap() as usize;
        let shared_mac_data = &buf[0..2];
    
        if size_expected == 0 {
            // Probably doesn't support EIP8
            // ACTUALLY... no it just have the discovery but no node (maybe someone doing like us)
            println!("[{}@{}:{}] Size expected is 0. Something is wrong.", hex::encode(&remote_id), ip, port);
            // let sk = k256::ecdsa::SigningKey::from_slice(&ephemeral_privkey).unwrap();
            // let ephemeral_pubkey = sk.verifying_key().to_encoded_point(false).to_bytes();

            // let init_msg = utils::create_auth_non_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &ephemeral_pubkey.to_vec());
            // // send the message
            // println!("Sending NON EIP8 Auth message");
            // stream.write(&init_msg).unwrap();
            // stream.flush().unwrap();

            // println!("waiting for answer...");
            // let mut buf = [0u8; 2];
            // let _size = stream.read(&mut buf);
            
            // let size_expected = buf.as_slice().read_u16::<BigEndian>().unwrap() as usize;
            // let shared_mac_data = &buf[0..2];

            // dbg!(&size_expected);

            return Err(Errors::EIP8Error(NodeId::new(&remote_id, &ip, port)));
        }

        let mut payload = vec![0u8; size_expected.into()];
        let result = stream.read_exact(&mut payload);
    
        if result.is_err() {
            return Err(Errors::UnknownError(NodeId::new(&remote_id, &ip, port)));
        }

    
        /******************
         * 
        *  Handle Ack
        * 
        ******************/
    
        println!("[{}@{}:{}] ACK message received", hex::encode(&remote_id), ip, port);
        let decrypted = utils::decrypt_message(&payload.to_vec(), &shared_mac_data.to_vec(), &private_key);
    
        // decode RPL data
        let rlp = rlp::Rlp::new(&decrypted);
        let mut rlp = rlp.into_iter();
    
        // id to pubkey
        let remote_public_key: Vec<u8> = [vec![0x04], rlp.next().unwrap().as_val().unwrap()].concat();
        let remote_nonce: Vec<u8> = rlp.next().unwrap().as_val().unwrap();
    
        let ephemeral_shared_secret = utils::ecdh_x(&remote_public_key, &ephemeral_privkey);
    
    
        /******************
         * 
        *  Setup Frame
        * 
        ******************/
        
        let remote_data = [shared_mac_data, &payload].concat();
        let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(remote_nonce, nonce, ephemeral_shared_secret, remote_data, init_msg);
    
        println!("[{}@{}:{}] Frame setup done !", hex::encode(&remote_id), ip, port);
    
        println!("[{}@{}:{}] Received Ack, waiting for Header", hex::encode(&remote_id), ip, port);
    
        /******************
         * 
        *  Handle HELLO
        * 
        ******************/
    
        let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);
    
        if uncrypted_body.is_err() {
            println!("[{}@{}:{}] Time out", hex::encode(&remote_id), ip, port);
            return Err(Errors::TimeOut(NodeId::new(&remote_id, &ip, port)));
        }
        let uncrypted_body = uncrypted_body.unwrap();

        if uncrypted_body[0] == 0x01 {
            // we have a disconnect message unfortunately
            println!("[{}@{}:{}] Disconnect {}", hex::encode(&remote_id), ip, port, hex::encode(uncrypted_body[1..].to_vec()));
            return Err(Errors::Disconnect(NodeId::new(&remote_id, &ip, port), uncrypted_body[1]));
        }

        // Should be HELLO
        assert_eq!(0x80, uncrypted_body[0]);
        let payload = rlp::decode::<types::HelloMessage>(&uncrypted_body[1..]);

        if payload.is_err() {
            println!("[{}@{}:{}] Couldn't read payload", hex::encode(&remote_id), ip, port);
            return Err(Errors::UnreadablePayload(NodeId::new(&remote_id, &ip, port), uncrypted_body[1..].to_vec()));
        }

        let hello_message = payload.unwrap();

        let capabilities = serde_json::to_string(&hello_message.capabilities).unwrap();

        // We need to find the highest eth version it supports
        let mut version = 0;
        for capability in hello_message.capabilities {
            if capability.name.0.to_string() == "eth" {
                if capability.version > version {
                    version = capability.version;
                }
            }
        }   

        /******************
         * 
        *  Create Hello
        * 
        ******************/
    
        println!("[{}@{}:{}] Sending HELLO message", hex::encode(&remote_id), ip, port);
        let hello = message::create_hello_message(&private_key);
        utils::send_message(hello, &mut stream, &mut egress_mac, &mut egress_aes);

        /******************
         * 
        *  Send STATUS message
        * 
        ******************/
    
        println!("[{}@{}:{}] Sending STATUS message", hex::encode(&remote_id), ip, port);
    
        let genesis_hash = [212,229,103,64,248,118,174,248,192,16,184,106,64,213,245,103,69,161,24,208,144,106,52,230,154,236,140,13,177,203,143,163].to_vec();
        let head_td = 0;
        let fork_id = [0xdce96c2d, 0].to_vec();
        let network_id = 1;
    
        let status = message::create_status_message(&version, &genesis_hash, &genesis_hash, &head_td, &fork_id, &network_id);
        utils::send_message(status, &mut stream, &mut egress_mac, &mut egress_aes);
    
        /******************
         * 
        *  Handle STATUS message
        * 
        ******************/
    
        println!("[{}@{}:{}] Handling STATUS message", hex::encode(&remote_id), ip, port);
        let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);
        if uncrypted_body.is_err() {
            println!("[{}@{}:{}] Time out", hex::encode(&remote_id), ip, port);
            return Err(Errors::TimeOut(NodeId::new(&remote_id, &ip, port)));
        }
        let uncrypted_body = uncrypted_body.unwrap();
        
        if uncrypted_body[0] == 0x01 {
            // we have a disconnect message unfortunately
            println!("[{}@{}:{}] Disconnect {}", hex::encode(&remote_id), ip, port, hex::encode(uncrypted_body[1..].to_vec()));
            return Err(Errors::Disconnect(NodeId::new(&remote_id, &ip, port), uncrypted_body[1]));
        }
        let network_id = message::parse_status_message(uncrypted_body[1..].to_vec());
    
        println!("[{}@{}:{}] networkid = {}", hex::encode(&remote_id), ip, port, &network_id    );

        return Ok(NodeInfo { remote_id, network_id, capabilities});
    })
    .collect();

    println!("Contacted all the nodes");

    let update_statement = postgres_client.prepare("UPDATE discv4.nodes SET network_id = $1, capabilities = $2 WHERE id = $3;").unwrap();
    let delete_statement = postgres_client.prepare("DELETE FROM discv4.nodes WHERE id = $1;").unwrap();

    result.iter()
        .for_each(|result| {
            match result {
                Ok(node) => {
                    trieur.entry(node.network_id).and_modify(|counter| *counter += 1 ).or_insert(1);
                    let cap : Vec<CapabilityMessage> = serde_json::from_str(&node.capabilities).unwrap();
                    let _result = postgres_client.execute(&update_statement, &[&(node.network_id as i64), &serde_json::to_value(&cap).unwrap(), &node.remote_id]).unwrap();
                },
                Err(e) => {
                    match e {
                        Errors::Disconnect(..) => {
                            disconnect_counter += 1;
                        },
                        Errors::EIP8Error(..) => {
                            eip8_error_counter += 1;
                        },
                        Errors::TimeOut(..) => {
                            timeout_counter += 1;
                        },
                        Errors::UnreachableNode(node) => {
                            println!("remove IP");
                            let _result = postgres_client.execute(&delete_statement, &[&node.id()]).unwrap();
                        },
                        Errors::UnreadablePayload(..) => {
                            unreadable_payload_counter += 1;
                        },
                        Errors::UnknownError(..) => { }
                    }
                }
            }
                
        });

    dbg!(&trieur);
    dbg!(&eip8_error_counter);
    dbg!(&disconnect_counter);
    dbg!(&timeout_counter);
    dbg!(&unreadable_payload_counter);


}
