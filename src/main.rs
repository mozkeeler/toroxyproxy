extern crate byteorder;
extern crate curl;
extern crate futures;
/*
extern crate tokio;
extern crate tokio_io;
*/
extern crate toroxide;
extern crate toroxide_openssl;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use curl::easy::Easy;
use std::convert::From;
use std::env;
use std::io::{Read, Write, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::net::TcpStream;
use std::thread::{self, spawn};
use std::time::Duration;
/*
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio_io::io::{ReadHalf, WriteHalf};
*/
use toroxide::{dir, types, Circuit, IdTracker};
use toroxide_openssl::{PendingTlsOpensslImpl, RsaSignerOpensslImpl, RsaVerifierOpensslImpl, TlsOpensslImpl};

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
//    } else if args[2] == "proxy" {
//        do_proxy(peers, circ_id_tracker);
    } else {
        panic!("unknown command '{}'", args[2]);
    }
}

/*
#[derive(Debug)]
enum PipeState {
    Reading,
    Writing,
}

#[derive(Debug)]
struct Pipe {
    read: ReadHalf<TcpStream>,
    write: WriteHalf<TcpStream>,
    state: PipeState,
    buffer: Vec<u8>,
    bytes_to_write: usize,
    buffer_offset: usize,
}

impl Pipe {
    fn new(read: ReadHalf<TcpStream>, write: WriteHalf<TcpStream>) -> Pipe {
        let mut buffer: Vec<u8> = Vec::with_capacity(2048);
        buffer.resize(2048, 0);
        Pipe {
            read,
            write,
            state: PipeState::Reading,
            buffer,
            bytes_to_write: 0,
            buffer_offset: 0,
        }
    }
}

impl Future for Pipe {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            match self.state {
                PipeState::Reading => {
                    let num_bytes_read = match self.read.poll_read(&mut self.buffer) {
                        Ok(async) => match async {
                            Async::Ready(num_bytes_read) => num_bytes_read,
                            Async::NotReady => return Ok(Async::NotReady),
                        }
                        Err(e) => return Err(e),
                    };
                    if num_bytes_read == 0 {
                        return Ok(Async::Ready(()));
                    }
                    self.state = PipeState::Writing;
                    self.bytes_to_write = num_bytes_read;
                    self.buffer_offset = 0;
                },
                PipeState::Writing => {
                    let to_write =
                        &self.buffer[self.buffer_offset..self.buffer_offset + self.bytes_to_write];
                    let bytes_written = match self.write.poll_write(to_write) {
                        Ok(async) => match async {
                            Async::Ready(bytes_written) => bytes_written,
                            Async::NotReady => return Ok(Async::NotReady),
                        }
                        Err(e) => return Err(e),
                    };
                    self.buffer_offset += bytes_written;
                    self.bytes_to_write -= bytes_written;
                    if self.bytes_to_write == 0 {
                        self.state = PipeState::Reading;
                        self.bytes_to_write = 0;
                        self.buffer_offset = 0;
                    }
                },
            }
        }
    }
}
*/

/*
fn do_proxy(peers: dir::TorPeerList, mut circ_id_tracker: IdTracker<u32>) {
    let addr = "127.0.0.1:1080".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    let server = listener.incoming().for_each(move |socket| {
        process(socket);
        Ok(())
    })
    .map_err(|err| {
        println!("accept error = {:?}", err);
    });
    tokio::run(server);
}
*/

/*
fn process(socket: TcpStream) {
    let buf: [u8; 9] = [0; 9];
    let socks4_connection = io::read_exact(socket, buf)
        .and_then(|(socket, buf)| {
            let mut reader = &buf[..];
            let version = reader.read_u8()?;
            if version != 4 {
                return Err(Error::new(ErrorKind::InvalidInput, "invalid version"));
                //return io::write_all(socket, vec![0, 0x5b]) // request rejected/failed code
            }
            let command = reader.read_u8()?;
            if command != 1 {
                return Err(Error::new(ErrorKind::InvalidInput, "invalid command"));
                //return io::write_all(socket, vec![0, 0x5b]); // request rejected/failed code
            }
            let port = reader.read_u16::<NetworkEndian>()?;
            let mut ip_addr: [u8; 4] = [0; 4];
            reader.read(&mut ip_addr)?;
            let ip_addr = Ipv4Addr::from(ip_addr);
            let null_terminator = reader.read_u8()?;
            if null_terminator != 0 {
                return Err(Error::new(ErrorKind::InvalidInput, "invalid user"));
                //return io::write_all(socket, vec![0, 0x5b]); // request rejected/failed code
            }
            let mut domain_buf: Vec<u8> = Vec::with_capacity(256);
            domain_buf.resize(256, 0);
            io::read_until(socket, 0, domain_buf).then(move |(socket, buf)| {
                let domain = String::from_utf8(buf).unwrap();
                Ok((socket, domain, SocketAddr::new(IpAddr::V4(ip_addr), port)))
            })
        })
        .and_then(|(client_socket, domain, ip_address, port)| {
            let mut outbuf: [u8; 8] = [0; 8];
            {
                let mut writer = &mut outbuf[..];
                writer.write_u8(0)?;
                writer.write_u8(0x5a)?;
                writer.write_u16::<NetworkEndian>(port)?;
                writer.write_all(&ip_address.octets())?;
            } // c'mon liveness detection :(
            io::write_all(client_socket, outbuf).then(move |(client_socket, _)| {
                Ok((client_socket, domain, port))
            })
        })
        .and_then(|(client_socket, domain, port)| {
            /*
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
            */
        })
        .and_then(|((client_socket, _), server_socket)| {
            let (read_client, write_client) = client_socket.split();
            let (read_server, write_server) = server_socket.split();
            Pipe::new(read_client, write_server)
            .join(Pipe::new(read_server, write_client))
        })
        .then(|_| Ok(()));
    tokio::spawn(socks4_connection);
}
*/

fn do_demo(peers: dir::TorPeerList, mut circ_id_tracker: IdTracker<u32>) {
    let mut circuit = setup_new_circuit(&peers, &mut circ_id_tracker).unwrap();
    loop {
        let result = match circuit.poll() {
            Ok(result) => result,
            Err(e) => {
                println!("error polling circuit: {}", e);
                return;
            }
        };
        println!("{:?}", result);
        thread::sleep(Duration::from_millis(100));
        match result {
            toroxide::Async::Ready(_) => break,
            toroxide::Async::NotReady => continue,
        }
    }
    /*
    let stream_id = circuit.begin("example.com:80").unwrap();
    println!("beginning stream {}", stream_id);
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
    println!("beginning stream {}", stream_id);
    let request = r#"GET / HTTP/1.1
Host: ip.seeip.org
User-Agent: toroxide/0.1.0
Connection: close

"#;
    circuit.send(stream_id, request.as_bytes()).unwrap();
    let response = circuit.recv_to_end().unwrap();
    print!("{}", String::from_utf8(response).unwrap());
    */
}

fn do_get(uri: &str) -> Result<Vec<u8>, curl::Error> {
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
) -> Result<Circuit<TlsOpensslImpl<TcpStream>, RsaVerifierOpensslImpl>, ()> {
    let circ_id = circ_id_tracker.get_new_id();
    let guard_node = match peers.get_guard_node(&mut EasyFetcher {}) {
        Some(node) => node,
        None => return Err(()),
    };
    let addr = SocketAddr::new(IpAddr::V4(guard_node.get_ip_addr()), guard_node.get_port());
    let stream = match TcpStream::connect(&addr) {
        Ok(stream) => stream,
        Err(_) => return Err(()),
    };
    match stream.set_nonblocking(true) {
        Ok(_) => {},
        Err(_) => return Err(()),
    }
    let mut pending_tls_impl = PendingTlsOpensslImpl::new(stream).unwrap();
    let mut tls_impl_option = None;
    loop {
        match pending_tls_impl.poll().unwrap() {
            toroxide::Async::Ready(tls_impl) => {
                tls_impl_option = Some(tls_impl);
                break;
            }
            toroxide::Async::NotReady => continue,
        }
        thread::sleep(Duration::from_millis(100));
    }
    let rsa_verifier = RsaVerifierOpensslImpl {};
    let rsa_signer = RsaSignerOpensslImpl::new();
    let circuit = Circuit::new(tls_impl_option.unwrap(), rsa_verifier, &rsa_signer, circ_id,
                               guard_node.get_ed25519_id_key());
    /*
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
    */
    Ok(circuit)
}
