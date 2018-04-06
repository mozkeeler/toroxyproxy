extern crate futures;
extern crate hyper;
extern crate tokio;
extern crate tokio_core;
extern crate toroxide;
extern crate toroxide_openssl;
/*
extern crate byteorder;
extern crate tokio_io;
*/

use futures::{Async, Future, IntoFuture, Stream};
use hyper::{Body, Chunk, Client, Uri};
use hyper::client::HttpConnector;
use std::io::{self, Error, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{env, str};
use tokio::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Handle};
use toroxide::{dir, Circuit, IdTracker};
use toroxide_openssl::{PendingTlsOpensslImpl, RsaSignerOpensslImpl, RsaVerifierOpensslImpl,
                       TlsOpensslImpl};

/*
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::convert::From;
use std::io::{Read, Write, Error, ErrorKind};
use std::net::TcpStream;
use std::thread::{self, spawn};
use std::time::Duration;
use tokio::io;
use tokio::prelude::*;
use tokio_io::io::{ReadHalf, WriteHalf};
*/

fn usage(program: &str) {
    println!("Usage: {} <directory server>:<port> <demo|proxy>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        usage(&args[0]);
        return;
    }
    let dir_server = &args[1];

    if args[2] == "demo" {
        do_demo(dir_server);
//    } else if args[2] == "proxy" {
//        do_proxy(peers, circ_id_tracker);
    } else {
        panic!("unknown command '{}'", args[2]);
    }
}

fn do_demo(dir_server: &str) {
    let mut core = Core::new().unwrap();
    let peers = get_peer_list(&mut core, dir_server).unwrap();
    let mut circ_id_tracker: IdTracker<u32> = IdTracker::new();
    let circuit = create_circuit(&mut core, dir_server, &peers, &mut circ_id_tracker).unwrap();

    let request = r#"GET / HTTP/1.1
Host: example.com
User-Agent: toroxide/0.1.0
Accept: text/html
Accept-Language: en-US,en;q=0.5
Connection: close

"#;
    let future = CircuitDataFuture {
        circuit: Some(circuit),
        hostport: "example.com:80".to_owned(),
        request: request.as_bytes().to_owned(),
    }.and_then(|(circuit, response)| {
        println!("{}", String::from_utf8(response).unwrap());
        let request = r#"GET / HTTP/1.1
Host: ip.seeip.org
User-Agent: toroxide/0.1.0
Connection: close

"#;
        CircuitDataFuture {
            circuit: Some(circuit),
            hostport: "ip.seeip.org:80".to_owned(),
            request: request.as_bytes().to_owned(),
        }
    }).and_then(|(_, response)| {
        println!("{}", String::from_utf8(response).unwrap());
        Ok(())
    });
    core.run(future).unwrap();
}

struct TlsStreamFuture {
    pending_tls_stream: PendingTlsOpensslImpl<TcpStream>,
}

impl Future for TlsStreamFuture {
    type Item = TlsOpensslImpl<TcpStream>;
    type Error = io::Error;

    // Remember, we can't return Async::NotReady unless we got it from something in the futures
    // world (not toroxide), so we just loop indefinitely here...
    fn poll(&mut self) -> Result<Async<TlsOpensslImpl<TcpStream>>, io::Error> {
        loop {
            match self.pending_tls_stream.poll()? {
                toroxide::Async::Ready(tls_stream) => {
                    println!("I guess we conencted?");
                    return Ok(Async::Ready(tls_stream));
                }
                toroxide::Async::NotReady => {},
            }
        }
    }
}

type OpensslCircuit = Circuit<TlsOpensslImpl<TcpStream>, RsaVerifierOpensslImpl>;

struct CircuitOpenFuture {
    circuit: Option<OpensslCircuit>,
}

impl Future for CircuitOpenFuture {
    type Item = OpensslCircuit;
    type Error = io::Error;

    // Remember, we can't return Async::NotReady unless we got it from something in the futures
    // world (not toroxide), so we just loop indefinitely here...
    fn poll(&mut self) -> Result<Async<OpensslCircuit>, io::Error> {
        let mut circuit = match self.circuit.take() {
            Some(circuit) => circuit,
            None => {
                println!("poll called with None circuit?");
                return Err(Error::new(ErrorKind::Other, "circuit should be Some here"));
            }
        };
        loop {
            match circuit.poll()? {
                toroxide::Async::Ready(()) => {
                    println!("I guess the circuit's ready?");
                    return Ok(Async::Ready(circuit));
                }
                toroxide::Async::NotReady => {},
            }
        }
    }
}

struct CircuitDirFuture {
    circuit: Option<OpensslCircuit>,
    pre_node: toroxide::dir::PreTorPeer,
    request: Vec<u8>,
}

impl CircuitDirFuture {
    fn new(circuit: OpensslCircuit, pre_node: toroxide::dir::PreTorPeer) -> CircuitDirFuture {
        let microdescriptor_path = pre_node.get_microdescriptor_path();
        let request = format!("GET {} HTTP/1.0\r\n\r\n", microdescriptor_path);
        println!("{}", request);
        CircuitDirFuture {
            circuit: Some(circuit),
            pre_node,
            request: request.as_bytes().to_owned(),
        }
    }
}

impl Future for CircuitDirFuture {
    type Item = (OpensslCircuit, Result<toroxide::dir::TorPeer, ()>);
    type Error = io::Error;

    fn poll(
        &mut self
    ) -> Result<Async<(OpensslCircuit, Result<toroxide::dir::TorPeer, ()>)>, io::Error> {
        let mut circuit = match self.circuit.take() {
            Some(circuit) => circuit,
            None => {
                println!("poll called with None circuit?");
                return Err(Error::new(ErrorKind::Other, "circuit should be Some here"));
            }
        };
        let stream_id = circuit.open_dir_stream();
        loop {
            match circuit.poll_dir(stream_id, &self.request)? {
                toroxide::Async::Ready(response) => {
                    let as_string = match String::from_utf8(response) {
                        Ok(as_string) => as_string,
                        Err(_) => return Ok(Async::Ready((circuit, Err(())))),
                    };
                    let index = match as_string.find("\r\n\r\n") {
                        Some(index) => index,
                        None => return Ok(Async::Ready((circuit, Err(())))),
                    };
                    let result = self.pre_node.to_tor_peer(&as_string[index + 4..]);
                    return Ok(Async::Ready((circuit, result)));
                }
                toroxide::Async::NotReady => {},
            }
        }
    }
}

struct CircuitExtendFuture {
    circuit: Option<OpensslCircuit>,
    node: toroxide::dir::TorPeer,
}

impl Future for CircuitExtendFuture {
    type Item = OpensslCircuit;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<OpensslCircuit>, io::Error> {
        let mut circuit = match self.circuit.take() {
            Some(circuit) => circuit,
            None => {
                println!("poll called with None circuit?");
                return Err(Error::new(ErrorKind::Other, "circuit should be Some here"));
            }
        };
        loop {
            match circuit.poll_extend(&self.node)? {
                toroxide::Async::Ready(()) => return Ok(Async::Ready(circuit)),
                toroxide::Async::NotReady => {},
            }
        }
    }
}

struct CircuitDataFuture {
    circuit: Option<OpensslCircuit>,
    hostport: String,
    request: Vec<u8>,
}

impl Future for CircuitDataFuture {
    type Item = (OpensslCircuit, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<(OpensslCircuit, Vec<u8>)>, io::Error> {
        let mut circuit = match self.circuit.take() {
            Some(circuit) => circuit,
            None => {
                println!("poll called with None circuit?");
                return Err(Error::new(ErrorKind::Other, "circuit should be Some here"));
            }
        };
        let stream_id = circuit.open_stream();
        loop {
            match circuit.poll_stream(stream_id, &self.hostport, &self.request)? {
                toroxide::Async::Ready(response) => return Ok(Async::Ready((circuit, response))),
                toroxide::Async::NotReady => {},
            }
        }
    }
}

fn get(
    client: &Client<HttpConnector, Body>,
    uri: Uri
) -> Box<Future<Item = Chunk, Error = io::Error>> {
    Box::new(client.get(uri).and_then(|res| {
        res.body().concat2()
    }).map_err(|e| Error::new(ErrorKind::Other, e)))
}

fn str_to_uri(uri: &str) -> io::Result<Uri> {
    uri.parse().map_err(|e| Error::new(ErrorKind::Other, e))
}

fn get_peer_list(core: &mut Core, dir_server: &str) -> io::Result<dir::TorPeerList> {
    let uri = format!("http://{}/tor/status-vote/current/consensus-microdesc/", dir_server);
    let uri = str_to_uri(&uri)?;
    let handle = core.handle();
    let client = Client::new(&handle);
    let work = get(&client, uri).and_then(|chunk| {
        let consensus = str::from_utf8(&chunk).map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(dir::TorPeerList::new(&consensus))
    });
    core.run(work)
}

fn create_circuit(
    core: &mut Core,
    dir_server: &str,
    peers: &dir::TorPeerList,
    circ_id_tracker: &mut IdTracker<u32>,
) -> io::Result<OpensslCircuit> {
    let pre_guard_node = peers.get_guard_node().expect("couldn't get guard node?").clone();
    let microdescriptor_uri = str_to_uri(&pre_guard_node.get_microdescriptor_uri(dir_server))?;
    let pre_interior_node = peers.get_interior_node(&[&pre_guard_node])
        .expect("couldn't get interior node?").clone();
    let pre_exit_node = peers.get_exit_node(&[&pre_guard_node, &pre_interior_node])
        .expect("couldn't get exit node?").clone();
    let circ_id = circ_id_tracker.get_new_id();

    let handle = core.handle();
    let client = Client::new(&handle);
    let work = get(&client, microdescriptor_uri).and_then(|chunk| {
        let microdescriptor = str::from_utf8(&chunk).unwrap();
        let guard_node = pre_guard_node.to_tor_peer(microdescriptor).unwrap();
        let addr = SocketAddr::new(IpAddr::V4(guard_node.get_ip_addr()), guard_node.get_port());
         TcpStream::connect(&addr).and_then(|stream| {
             Ok((stream, guard_node))
         })
    }).and_then(|(stream, guard_node)| {
        // TODO: how do we handle errors inside these things?
        let pending_tls_stream = PendingTlsOpensslImpl::new(stream).unwrap();
        (TlsStreamFuture { pending_tls_stream }).and_then(|tls_stream| {
            Ok((tls_stream, guard_node))
        })
    }).and_then(|(tls_stream, guard_node)| {
        println!("I guess we're here?");
        let rsa_verifier = RsaVerifierOpensslImpl {};
        let rsa_signer = RsaSignerOpensslImpl::new();
        let circuit = Circuit::new(tls_stream, rsa_verifier, &rsa_signer, circ_id,
                                   guard_node.get_ed25519_id_key());
        CircuitOpenFuture { circuit: Some(circuit) }.and_then(move |circuit| {
            CircuitDirFuture::new(circuit, pre_interior_node)
        }).and_then(|(circuit, interior_node)| {
            Ok((circuit, interior_node))
        })
    }).and_then(|(circuit, interior_node)| {
        (CircuitExtendFuture {
            circuit: Some(circuit),
            node: interior_node.unwrap(),
        }).and_then(|circuit| {
            CircuitDirFuture::new(circuit, pre_exit_node)
        })
    }).and_then(|(circuit, exit_node)| {
        CircuitExtendFuture {
            circuit: Some(circuit),
            node: exit_node.unwrap(),
        }
    });
    core.run(work)
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
