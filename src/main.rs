extern crate byteorder;
extern crate curl;
extern crate toroxide;
extern crate toroxide_openssl;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use curl::Error;
use curl::easy::Easy;
use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::thread::spawn;
use std::time::Duration;
use toroxide::{dir, types, Circuit, IdTracker};
use toroxide_openssl::{RsaSignerOpensslImpl, RsaVerifierOpensslImpl, TlsOpensslImpl};

fn usage(program: &str) {
    println!("Usage: {} <directory server>:<port> <demo|proxy>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        usage(&args[0]);
        return;
    }
    let peers = get_tor_peers(&args[1]).unwrap();
    let circ_id_tracker: IdTracker<u32> = IdTracker::new();

    if args[2] == "demo" {
        do_demo(peers, circ_id_tracker);
    } else if args[2] == "proxy" {
        do_proxy(peers, circ_id_tracker);
    } else {
        panic!("unknown command '{}'", args[2]);
    }
}

fn do_proxy(peers: dir::TorPeerList, mut circ_id_tracker: IdTracker<u32>) {
    let listener = TcpListener::bind("127.0.0.1:1080").unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut buf: [u8; 1024] = [0; 1024];
        stream.read(&mut buf).unwrap();
        let mut reader = &buf[..];
        let version = reader.read_u8().unwrap();
        if version != 4 {
            println!("unexpected version field {}", version);
            continue; // TODO: respond with correct socks error message?
        }
        let command = reader.read_u8().unwrap();
        if command != 1 {
            println!("unexpected command {}", command);
            continue; // TODO same
        }
        let port = reader.read_u16::<NetworkEndian>().unwrap();
        let ip_addr = reader.read_u32::<NetworkEndian>().unwrap();
        if ip_addr > 255 {
            println!("unexpected invalid ip address {}", ip_addr);
            continue;
        }
        let null_terminator = reader.read_u8().unwrap();
        if null_terminator != 0 {
            println!("expected zero-length username");
            continue;
        }
        let mut str_buf: Vec<u8> = Vec::new();
        loop {
            let byte = reader.read_u8().unwrap();
            if byte == 0 {
                break;
            }
            str_buf.push(byte);
        }
        let domain = String::from_utf8(str_buf).unwrap();

        let mut outbuf: [u8; 8] = [0; 8];
        {
            let mut writer = &mut outbuf[..];
            writer.write_u8(0).unwrap();
            writer.write_u8(0x5a).unwrap();
            writer.write_u16::<NetworkEndian>(port).unwrap();
            writer.write_u32::<NetworkEndian>(ip_addr).unwrap();
        } // c'mon liveness detection :(
        stream.write_all(&outbuf).unwrap();
        let mut retries = 5;
        let mut circuit_result = setup_new_circuit(&peers, &mut circ_id_tracker);
        while circuit_result.is_err() && retries > 0 {
            circuit_result = setup_new_circuit(&peers, &mut circ_id_tracker);
            retries -= 1;
        }
        let mut circuit = match circuit_result {
            Ok(circuit) => circuit,
            Err(_) => break,
        };
        let dest = format!("{}:{}", domain, port);
        let stream_id = match circuit.begin(&dest) {
            Ok(stream_id) => stream_id,
            Err(_) => break,
        };

        stream
            .set_read_timeout(Some(Duration::from_millis(16)))
            .unwrap();

        let mut stop = false;
        spawn(move || loop {
            if stop {
                break;
            }
            let mut buf: [u8; types::RELAY_PAYLOAD_LEN] = [0; types::RELAY_PAYLOAD_LEN];
            loop {
                let len = match stream.read(&mut buf) {
                    Ok(len) => len,
                    Err(_) => break,
                };
                circuit.send(stream_id, &buf[..len]).unwrap();
            }
            loop {
                // If this returns an error, either there was nothing to read or we read invalid
                // data ( :/ ) so just go around again...?
                let response = match circuit.recv() {
                    Ok(response) => response,
                    Err(_) => break,
                };
                // If the response is length 0, either we got a cell of length 0 or a RELAY_END. We
                // really need to figure out the signalling story here...
                if response.len() == 0 {
                    stop = true;
                    break;
                }
                stream.write_all(&response).unwrap();
            }
        });
    }
}

fn do_demo(peers: dir::TorPeerList, mut circ_id_tracker: IdTracker<u32>) {
    let mut circuit = setup_new_circuit(&peers, &mut circ_id_tracker).unwrap();
    let stream_id = circuit.begin("example.com:80").unwrap();
    let request = r#"GET / HTTP/1.1
Host: example.com
User-Agent: toroxide/0.1.0
Accept: text/html
Accept-Language: en-US,en;q=0.5
Connection: close

"#;
    circuit.send(stream_id, request.as_bytes()).unwrap();
    let response = circuit.recv_to_end().unwrap();
    print!("{}", String::from_utf8(response).unwrap());

    let stream_id = circuit.begin("ip.seeip.org:80").unwrap();
    let request = r#"GET / HTTP/1.1
Host: ip.seeip.org
User-Agent: toroxide/0.1.0
Connection: close

"#;
    circuit.send(stream_id, request.as_bytes()).unwrap();
    let response = circuit.recv_to_end().unwrap();
    print!("{}", String::from_utf8(response).unwrap());
}

fn do_get(uri: &str) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    let mut handle = Easy::new();
    handle.url(uri)?;
    {
        // Ok this is for sure poor API design, though.
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }
    Ok(data)
}

struct EasyFetcher {}

impl dir::Fetch for EasyFetcher {
    fn fetch(&mut self, uri: &str) -> Result<Vec<u8>, ()> {
        match do_get(uri) {
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(()),
        }
    }
}

pub fn get_tor_peers(hostport: &str) -> Result<dir::TorPeerList, ()> {
    let uri = format!(
        "http://{}/tor/status-vote/current/consensus-microdesc/",
        hostport
    );
    let data = match do_get(&uri) {
        Ok(data) => data,
        Err(_) => return Err(()),
    };
    let as_string = match String::from_utf8(data) {
        Ok(as_string) => as_string,
        Err(_) => return Err(()),
    };
    Ok(dir::TorPeerList::new(hostport, &as_string))
}

pub fn setup_new_circuit(
    peers: &dir::TorPeerList,
    circ_id_tracker: &mut IdTracker<u32>,
) -> Result<Circuit<TlsOpensslImpl, RsaVerifierOpensslImpl, RsaSignerOpensslImpl>, ()> {
    let circ_id = circ_id_tracker.get_new_id();
    let guard_node = match peers.get_guard_node(&mut EasyFetcher {}) {
        Some(node) => node,
        None => return Err(()),
    };
    let tls_impl =
        TlsOpensslImpl::connect(IpAddr::V4(guard_node.get_ip_addr()), guard_node.get_port())
            .unwrap();
    let rsa_verifier = RsaVerifierOpensslImpl {};
    let rsa_signer = RsaSignerOpensslImpl::new();
    let mut circuit = Circuit::new(tls_impl, rsa_verifier, rsa_signer, circ_id);
    circuit.negotiate_versions()?;
    circuit.read_certs(&guard_node.get_ed25519_id_key())?;
    circuit.read_auth_challenge()?;
    circuit.send_certs_and_authenticate_cells()?;
    circuit.read_netinfo()?;
    circuit.create_fast()?;
    let interior_node = {
        let mut fetcher = dir::CircuitDirectoryFetcher::new(&mut circuit);
        match peers.get_interior_node(&[&guard_node], &mut fetcher) {
            Some(node) => node,
            None => return Err(()),
        }
    };
    circuit.extend(&interior_node)?;
    let exit_node = {
        let mut fetcher = dir::CircuitDirectoryFetcher::new(&mut circuit);
        match peers.get_exit_node(&[&guard_node, &interior_node], &mut fetcher) {
            Some(node) => node,
            None => return Err(()),
        }
    };
    circuit.extend(&exit_node)?;
    Ok(circuit)
}
