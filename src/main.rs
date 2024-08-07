use std::{net::TcpStream, time::Duration};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::prelude::*;
use std::net::SocketAddr;
use tokio_postgres::NoTls;
use secp256k1::{rand, SecretKey};
use secp256k1::rand::RngCore;

pub mod utils;
pub mod mac;
pub mod message;
pub mod types;
pub mod errors;
pub mod config;

use crate::types::CapabilityMessage;

#[tokio::main]
async fn main() {
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


    let (postgres_client, connection) =
        tokio_postgres::connect(&database_params, NoTls).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let records = postgres_client.query("SELECT * FROM discv4.nodes WHERE network_id IS NULL ORDER BY RANDOM();", &[]).await.unwrap();


    let update_statement = postgres_client.prepare("UPDATE discv4.nodes SET network_id = $1, capabilities = $2 WHERE id = $3;").await.unwrap();
    let delete_statement = postgres_client.prepare("DELETE FROM discv4.nodes WHERE id = $1;").await.unwrap();

    let _ = futures::future::join_all(records.iter().map(|record| async {
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
            let _result = postgres_client.execute(&delete_statement, &[&remote_id]).await.unwrap();
            return
        }

        let mut stream = stream.unwrap();
        // Set read timeout
        stream.set_read_timeout(Some(Duration::from_millis(5000))).unwrap();

        let private_key = SecretKey::new(&mut rand::thread_rng())
        .secret_bytes()
        .to_vec();
        let mut nonce = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ephemeral_privkey = SecretKey::new(&mut rand::thread_rng())
            .secret_bytes()
            .to_vec();
        let pad = vec![0; 100]; // should be generated randomly but we don't really care
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
            println!("[{}@{}:{}] EIP8 error", hex::encode(&remote_id), ip, port);
            
            let _result = postgres_client.execute(&delete_statement, &[&remote_id]).await.unwrap();
            return
        }

        let mut payload = vec![0u8; size_expected.into()];
        let result = stream.read_exact(&mut payload);
    
        if result.is_err() {
            println!("[{}@{}:{}] Unknown error", hex::encode(&remote_id), ip, port);
            let _result = postgres_client.execute(&delete_statement, &[&remote_id]).await.unwrap();
            return
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
            return
        }
        let uncrypted_body = uncrypted_body.unwrap();

        if uncrypted_body[0] == 0x01 {
            // we have a disconnect message unfortunately
            println!("[{}@{}:{}] Disconnect {}", hex::encode(&remote_id), ip, port, hex::encode(uncrypted_body[1..].to_vec()));
            return
        }

        // Should be HELLO
        assert_eq!(0x80, uncrypted_body[0]);
        let payload = rlp::decode::<types::HelloMessage>(&uncrypted_body[1..]);

        if payload.is_err() {
            println!("[{}@{}:{}] Couldn't read payload", hex::encode(&remote_id), ip, port);
            return 
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
    
        let genesis_hash = [
            212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69, 161,
            24, 208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
        ].to_vec();
        let head_td = 0;
        let fork_id = [0x9f3d2254, 0].to_vec();
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
            return
        }
        let uncrypted_body = uncrypted_body.unwrap();
        
        if uncrypted_body[0] == 0x01 {
            // we have a disconnect message unfortunately
            println!("[{}@{}:{}] Disconnect {}", hex::encode(&remote_id), ip, port, hex::encode(uncrypted_body[1..].to_vec()));
            return
        }
        let network_id = message::parse_status_message(uncrypted_body[1..].to_vec());
    
        println!("[{}@{}:{}] networkid = {}", hex::encode(&remote_id), ip, port, &network_id);

        let cap : Vec<CapabilityMessage> = serde_json::from_str(&capabilities).unwrap();
        let _result = postgres_client.execute(&update_statement, &[&(network_id as i64), &serde_json::to_value(&cap).unwrap(), &remote_id]).await.unwrap();
    })).await;

    println!("Contacted all the nodes");
}
