extern crate byteorder;
extern crate tokio;
extern crate tokio_io;
extern crate toroxide;
extern crate toroxide_openssl;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::env;
use std::str;
use tokio::io::{read_to_end, read_exact, write_all};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::{Async, Future, Stream};
use tokio_io::{AsyncRead, AsyncWrite};
use toroxide::{dir, Circuit, IdTracker};
use toroxide_openssl::{PendingTlsOpensslImpl, RsaSignerOpensslImpl, RsaVerifierOpensslImpl,
                       TlsOpensslImpl};

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
        do_demo(dir_server).unwrap();
    } else if args[2] == "proxy" {
        do_proxy(dir_server.to_owned());
    } else {
        panic!("unknown command '{}'", args[2]);
    }
}

fn do_demo(dir_server: &str) -> Result<(), io::Error> {
    let peers = get_peer_list(dir_server)?;
    let mut circ_id_tracker: IdTracker<u32> = IdTracker::new();
    let circ_id = circ_id_tracker.get_new_id();
    let pre_guard_node = peers.get_guard_node().expect("couldn't get guard node?").clone();
    let pre_interior_node = peers.get_interior_node(&[&pre_guard_node])
        .expect("couldn't get interior node?").clone();
    let pre_exit_node = peers.get_exit_node(&[&pre_guard_node, &pre_interior_node])
        .expect("couldn't get exit node?").clone();
    let nodes = [pre_guard_node, pre_interior_node, pre_exit_node];
    let task = create_circuit(dir_server, nodes, circ_id).and_then(|circuit| {
        let request = r#"GET / HTTP/1.1
Host: example.com
User-Agent: toroxide/0.1.0
Accept: text/html
Accept-Language: en-US,en;q=0.5
Connection: close

"#;
        let hostport = "example.com:80";
        CircuitDataFuture::new(circuit, hostport, request.as_bytes())
    }).and_then(|(circuit, response)| {
        println!("{}", String::from_utf8(response).unwrap());
        let request = r#"GET / HTTP/1.1
Host: ip.seeip.org
User-Agent: toroxide/0.1.0
Connection: close

"#;
        let hostport = "ip.seeip.org:80";
        CircuitDataFuture::new(circuit, hostport, request.as_bytes())
    }).and_then(|(_, response)| {
        println!("{}", String::from_utf8(response).unwrap());
        Ok(())
    }).then(|_| Ok(()));
    tokio::run(task);
    Ok(())
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

enum CircuitDirFutureState {
    Setup,
    RequestWriting,
    ResponseReading,
}

struct CircuitDirFuture {
    circuit: Option<OpensslCircuit>,
    pre_node: toroxide::dir::PreTorPeer,
    request: Vec<u8>,
    response: Vec<u8>,
    state: CircuitDirFutureState,
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
            response: Vec::new(),
            state: CircuitDirFutureState::Setup,
        }
    }
}

impl Future for CircuitDirFuture {
    type Item = (OpensslCircuit, Result<toroxide::dir::TorPeer, ()>);
    type Error = io::Error;

    fn poll(
        &mut self,
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
            match self.state {
                CircuitDirFutureState::Setup => {
                    match circuit.poll_stream_setup(stream_id)? {
                        toroxide::Async::Ready(()) => self.state = CircuitDirFutureState::RequestWriting,
                        toroxide::Async::NotReady => continue,
                    }
                }
                CircuitDirFutureState::RequestWriting => {
                    match circuit.poll_stream_write(stream_id, &self.request)? {
                        toroxide::Async::Ready(()) => self.state = CircuitDirFutureState::ResponseReading,
                        toroxide::Async::NotReady => continue,
                    }
                }
                CircuitDirFutureState::ResponseReading => {
                    match circuit.poll_stream_read(stream_id)? {
                        toroxide::Async::Ready(mut response) => {
                            // We've reached the end of what we're being sent if we get a
                            // zero-length response (although right now toroxide doesn't enforce
                            // that peers don't send us zero-length DATA cells...)
                            if response.len() == 0 {
                                let as_string = match str::from_utf8(&self.response) {
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
                            self.response.append(&mut response);
                        }
                        toroxide::Async::NotReady => {},
                    }
                }
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

enum CircuitDataFutureState {
    Setup,
    Writing,
    Reading,
}

struct CircuitDataFuture {
    circuit: Option<OpensslCircuit>,
    hostport: String,
    request: Vec<u8>,
    response: Vec<u8>,
    state: CircuitDataFutureState,
}

impl CircuitDataFuture {
    fn new(circuit: OpensslCircuit, hostport: &str, request: &[u8]) -> CircuitDataFuture {
        CircuitDataFuture {
            circuit: Some(circuit),
            hostport: hostport.to_owned(),
            request: request.to_owned(),
            response: Vec::new(),
            state: CircuitDataFutureState::Setup,
        }
    }
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
        let stream_id = circuit.open_stream(&self.hostport);
        loop {
            match self.state {
                CircuitDataFutureState::Setup => {
                    match circuit.poll_stream_setup(stream_id)? {
                        toroxide::Async::Ready(()) => self.state = CircuitDataFutureState::Writing,
                        toroxide::Async::NotReady => continue,
                    }
                }
                CircuitDataFutureState::Writing => {
                    match circuit.poll_stream_write(stream_id, &self.request)? {
                        toroxide::Async::Ready(()) => self.state = CircuitDataFutureState::Reading,
                        toroxide::Async::NotReady => continue,
                    }
                }
                CircuitDataFutureState::Reading => {
                    match circuit.poll_stream_read(stream_id)? {
                        toroxide::Async::Ready(mut response) => {
                            if response.len() == 0 {
                                return Ok(Async::Ready((circuit, self.response.clone())));
                            }
                            self.response.append(&mut response);
                        }
                        toroxide::Async::NotReady => {},
                    }
                }
            }
        }
    }
}

// Synchronously fetches the peer list from the directory server.
fn get_peer_list(dir_server: &str) -> io::Result<dir::TorPeerList> {
    let mut stream = std::net::TcpStream::connect(dir_server)?;
    let request = "GET /tor/status-vote/current/consensus-microdesc/ HTTP/1.0\r\n\r\n";
    stream.write_all(request.as_bytes())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let index = match buf.find("\r\n\r\n") {
        Some(index) => index,
        None => return Err(Error::new(ErrorKind::Other, "bad response from directory server")),
    };
    println!("returning '{}'", &buf[index + 4..]);
    Ok(dir::TorPeerList::new(&buf[index + 4..]))
}

fn async_get_microdescriptor(
    dir_server: &str,
    microdescriptor_path: String,
) -> Box<Future<Item = String, Error = io::Error> + Send> {
    // TODO: tokio doesn't re-export future::err?
    // TODO: support domain names as well
    let socket_addr = dir_server.parse().unwrap();
    Box::new(TcpStream::connect(&socket_addr).and_then(move |stream| {
        let request = format!("GET {} HTTP/1.0\r\n\r\n", microdescriptor_path);
        write_all(stream, request.clone())
    }).and_then(|(stream, _)| {
        let buf = Vec::new();
        read_to_end(stream, buf)
    }).and_then(|(_, buf)| {
        let as_string = String::from_utf8(buf).map_err(|e| Error::new(ErrorKind::Other, e))?;
        let index = match as_string.find("\r\n\r\n") {
            Some(index) => index,
            None => return Err(Error::new(ErrorKind::Other, "bad response from directory server")),
        };
        Ok(as_string[index + 4..].to_owned())
    }))
}

fn create_circuit(
    dir_server: &str,
    nodes: [dir::PreTorPeer; 3],
    circ_id: u32,
) -> Box<Future<Item = OpensslCircuit, Error = io::Error> + Send> {
    let pre_guard_node = nodes[0].clone();
    let microdescriptor_path = pre_guard_node.get_microdescriptor_path();
    let pre_interior_node = nodes[1].clone();
    let pre_exit_node = nodes[2].clone();

    Box::new(async_get_microdescriptor(dir_server, microdescriptor_path)
        .and_then(move |microdescriptor| {
            let guard_node = pre_guard_node.to_tor_peer(&microdescriptor).unwrap();
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
    }).and_then(move |(tls_stream, guard_node)| {
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
    }))
}

enum CircuitPipeState {
    Setup,
    Ready,
}

struct CircuitPipe {
    circuit: Option<OpensslCircuit>,
    stream: Option<TcpStream>,
    domain: String,
    port: u16,
    state: CircuitPipeState,
}

impl CircuitPipe {
    fn new(circuit: OpensslCircuit, stream: TcpStream, domain: String, port: u16) -> CircuitPipe {
        CircuitPipe {
            circuit: Some(circuit),
            stream: Some(stream),
            domain,
            port,
            state: CircuitPipeState::Setup,
        }
    }

    fn socket_to_circuit(
        &self,
        stream: &mut TcpStream,
        circuit: &mut OpensslCircuit,
        stream_id: u16,
    ) -> Result<Async<()>, io::Error> {
        let mut buf = Vec::with_capacity(498);
        match stream.read_buf(&mut buf)? {
            Async::Ready(n) => {
                // TODO polling here...?
                circuit.poll_stream_write(stream_id, &buf)?;
            }
            Async::NotReady => {}
        }
        Ok(Async::NotReady)
    }

    fn circuit_to_socket(
        &self,
        circuit: &mut OpensslCircuit,
        stream: &mut TcpStream,
        stream_id: u16,
    ) -> Result<Async<()>, io::Error> {
        match circuit.poll_stream_read(stream_id)? {
            toroxide::Async::Ready(data) => {
                // TODO polling here...?
                let mut offset = 0;
                loop {
                    match stream.poll_write(&data[offset..])? {
                        Async::Ready(n) => {
                            offset += n;
                            if offset == data.len() {
                                break;
                            }
                        }
                        Async::NotReady => {}
                    }
                }
            }
            toroxide::Async::NotReady => {}
        }
        Ok(Async::NotReady)
    }
}

impl Future for CircuitPipe {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<()>, io::Error> {
        let mut circuit = match self.circuit.take() {
            Some(circuit) => circuit,
            None => return Err(Error::new(ErrorKind::Other, "circuit should be Some here")),
        };
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => return Err(Error::new(ErrorKind::Other, "stream should be Some here")),
        };
        let hostport = format!("{}:{}", self.domain, self.port);
        let stream_id = circuit.open_stream(&hostport);
        loop {
            match self.state {
                CircuitPipeState::Setup => {
                    match circuit.poll_stream_setup(stream_id)? {
                        toroxide::Async::Ready(()) => self.state = CircuitPipeState::Ready,
                        toroxide::Async::NotReady => continue,
                    }
                }
                CircuitPipeState::Ready => {
                    let result = self.socket_to_circuit(&mut stream, &mut circuit, stream_id);
                    if result.is_err() {
                        println!("socket_to_circuit: {:?}", result);
                        return result;
                    }
                    let result = self.circuit_to_socket(&mut circuit, &mut stream, stream_id);
                    if result.is_err() {
                        println!("circuit_to_socket: {:?}", result);
                        return result;
                    }
                }
            }
        }
    }
}

fn do_proxy(dir_server: String) {
    let peers = get_peer_list(&dir_server).unwrap();
    let mut circ_id_tracker: IdTracker<u32> = IdTracker::new();

    let addr = "127.0.0.1:1080".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    let server = listener.incoming().for_each(move |socket| {
        let pre_guard_node = peers.get_guard_node().expect("couldn't get guard node?").clone();
        let pre_interior_node = peers.get_interior_node(&[&pre_guard_node])
            .expect("couldn't get interior node?").clone();
        let pre_exit_node = peers.get_exit_node(&[&pre_guard_node, &pre_interior_node])
            .expect("couldn't get exit node?").clone();
        let nodes = [pre_guard_node, pre_interior_node, pre_exit_node];
        process(socket, dir_server.clone(), nodes, circ_id_tracker.get_new_id());
        Ok(())
    })
    .map_err(|err| {
        println!("accept error = {:?}", err);
    });
    tokio::run(server);
}

struct ReadUntil {
    stream: Option<TcpStream>,
    buffer: Vec<u8>,
}

impl Future for ReadUntil {
    type Item = (TcpStream, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<(TcpStream, Vec<u8>)>, io::Error> {
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => return Err(Error::new(ErrorKind::Other, "stream should be Some here")),
        };
        loop {
            let mut buf: [u8; 1] = [0; 1];
            match stream.poll_read(&mut buf)? {
                Async::Ready(n) => {
                    println!("got some data...");
                    if n == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "unexpected eof"));
                    }
                    if buf[0] == 0 {
                        return Ok(Async::Ready((stream, self.buffer.clone())));
                    }
                    self.buffer.push(buf[0]);
                }
                Async::NotReady => {}
            }
        }
    }
}

fn process(socket: TcpStream, dir_server: String, nodes: [dir::PreTorPeer; 3], circ_id: u32) -> () {
    let buf: [u8; 9] = [0; 9];
    let socks4_connection = read_exact(socket, buf).and_then(|(socket, buf)| {
        let mut reader = &buf[..];
        let version = reader.read_u8().unwrap();
        /*
        if version != 4 {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid version"));
            //return tokio::io::write_all(socket, vec![0, 0x5b]) // request rejected/failed code
        }
        */
        let command = reader.read_u8().unwrap();
        /*
        if command != 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid command"));
            //return tokio::io::write_all(socket, vec![0, 0x5b]); // request rejected/failed code
        }
        */
        let port = reader.read_u16::<NetworkEndian>().unwrap();
        let mut ip_addr: [u8; 4] = [0; 4];
        reader.read(&mut ip_addr).unwrap();
        let null_terminator = reader.read_u8().unwrap();
        /*
        if null_terminator != 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid user"));
            //return tokio::io::write_all(socket, vec![0, 0x5b]); // request rejected/failed code
        }
        */
        let mut domain_buf: Vec<u8> = Vec::with_capacity(256);
        domain_buf.resize(256, 0);
        ReadUntil { stream: Some(socket), buffer: Vec::new() }.and_then(move |(socket, buf)| {
            let domain = String::from_utf8(buf).unwrap();
            Ok((socket, domain, ip_addr, port))
        })
    }).and_then(|(client_socket, domain, ip_address, port)| {
        let mut outbuf: [u8; 8] = [0; 8];
        {
            let mut writer = &mut outbuf[..];
            writer.write_u8(0).unwrap();
            writer.write_u8(0x5a).unwrap();
            writer.write_u16::<NetworkEndian>(port).unwrap();
            writer.write_all(&ip_address).unwrap();
        } // c'mon liveness detection :(
        write_all(client_socket, outbuf).and_then(move |(client_socket, _buf)| {
            Ok((client_socket, domain, port))
        })
    }).and_then(move |(client_socket, domain, port)| {
        println!("should connect to {}:{}", domain, port);
        create_circuit(&dir_server, nodes, circ_id).and_then(move |circuit| {
            Ok((circuit, client_socket, domain, port))
        })
    }).and_then(|(circuit, stream, domain, port)| {
        println!("created circuit?");
        CircuitPipe::new(circuit, stream, domain, port)
    }).then(|_| Ok(()));
    tokio::spawn(socks4_connection);
}
