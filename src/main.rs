extern crate byteorder;
extern crate toroxide;
extern crate toroxide_openssl;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::{env, str, thread};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use toroxide::{Async, Circuit, IdTracker};
use toroxide::dir::{PreTorPeer, TorPeer, TorPeerList};
use toroxide_openssl::{PendingTlsOpensslImpl, RsaSignerOpensslImpl, RsaVerifierOpensslImpl,
                       TlsOpensslImpl};

fn usage(program: &str) {
    println!("Usage: {} <directory server>:<port>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        usage(&args[0]);
        return;
    }
    let dir_server = &args[1];
    do_proxy(dir_server.to_owned()).unwrap();
}

fn do_proxy(dir_server: String) -> Result<(), Error> {
    let listener = TcpListener::bind("127.0.0.1:1080")?;
    // TODO: increase this to pipeline more requests?
    let (tx, rx): (SyncSender<TcpStream>, Receiver<TcpStream>) = sync_channel(0);
    let socks_thread_handle = thread::spawn(move || socks_thread(dir_server.to_owned(), rx));
    println!("listening?");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => match tx.send(stream) {
                Ok(()) => {},
                Err(e) => {
                    println!("error sending stream: {:?}", e);
                    break;
                }
            }
            Err(e) => {
                println!("error accepting connection: {:?}", e);
                break;
            }
        }
    }
    socks_thread_handle.join().map_err(|_| Error::new(ErrorKind::Other, "couldn't join thread?"))?;
    Ok(())
}

type SocksPrelude = (TcpStream, String, u16);
fn socks_thread(dir_server: String, stream_rx: Receiver<TcpStream>) {
    let (tx, rx) : (SyncSender<SocksPrelude>, Receiver<SocksPrelude>) = sync_channel(0);
    let pipe_thread_handle = thread::spawn(move || pipe_thread(dir_server, rx));
    loop {
        match stream_rx.recv() {
            Ok(stream) => match socks4a_prelude(stream, &tx) {
                Ok(()) => {},
                Err(e) => {
                    println!("socks4a_prelude failed: {:?}", e);
                    break;
                }
            }
            Err(e) => {
                println!("stream_rx.recv() failed: {:?}", e);
                break;
            }
        }
    }
    pipe_thread_handle.join().unwrap();
}

fn socks4a_prelude(mut stream: TcpStream, tx: &SyncSender<SocksPrelude>) -> Result<(), Error> {
    let mut buf: [u8; 9] = [0; 9];
    stream.read_exact(&mut buf)?;
    let mut reader = &buf[..];
    let version = reader.read_u8()?;
    if version != 4 {
        stream.write_all(&[0x00, 0x5b])?;
        return Err(Error::new(ErrorKind::InvalidInput, "invalid version"));
    }
    let command = reader.read_u8()?;
    if command != 1 {
        stream.write_all(&[0x00, 0x5b])?;
        return Err(Error::new(ErrorKind::InvalidInput, "invalid command"));
    }
    let port = reader.read_u16::<NetworkEndian>()?;
    let mut ip_addr: [u8; 4] = [0; 4];
    reader.read(&mut ip_addr)?;
    let null_terminator = reader.read_u8()?;
    if null_terminator != 0 {
        stream.write_all(&[0x00, 0x5b])?;
        return Err(Error::new(ErrorKind::InvalidInput, "non-null users not supported"));
    }
    let mut domain_buf: Vec<u8> = Vec::with_capacity(256);
    loop {
        let mut buf: [u8; 1] = [0; 1];
        stream.read_exact(&mut buf)?;
        if buf[0] == 0 {
            break;
        }
        domain_buf.extend(buf.iter());
    }
    let domain = match String::from_utf8(domain_buf) {
        Ok(domain) => domain,
        Err(_) => {
            stream.write_all(&[0x00, 0x5b])?;
            return Err(Error::new(ErrorKind::InvalidInput, "invalid domain name"));
        }
    };
    let mut outbuf: [u8; 8] = [0; 8];
    {
        let mut writer = &mut outbuf[..];
        writer.write_u8(0)?;
        writer.write_u8(0x5a)?;
        writer.write_u16::<NetworkEndian>(port)?;
        writer.write_all(&ip_addr)?;
    } // c'mon liveness detection :(
    stream.write_all(&mut outbuf)?;
    match tx.send((stream, domain, port)) {
        Ok(()) => Ok(()),
        Err(e) => {
            println!("failed to send socks prelude: {:?}", e);
            Err(Error::new(ErrorKind::Other, e))
        }
    }
}

fn pipe_thread(dir_server: String, mut socks_rx: Receiver<SocksPrelude>) {
    let (tx, rx) : (SyncSender<OpensslCircuit>, Receiver<OpensslCircuit>) = sync_channel(0);
    let circuit_creation_thread_handle = thread::spawn(move || {
        circuit_creation_thread(dir_server, tx);
    });
    let mut num_circuits_received = 0;
    loop {
        let circuit = match rx.recv() {
            Ok(circuit) => circuit,
            Err(e) => {
                println!("couldn't receive circuit? ({:?})", e);
                break;
            }
        };
        num_circuits_received += 1;
        println!("received {} total circuits", num_circuits_received);
        let mut piper = CircuitPiper::new(circuit, &mut socks_rx);
        loop {
            let async = match piper.poll() {
                Ok(async) => async,
                Err(e) => {
                    println!("error from piper: {:?}", e);
                    break;
                }
            };
            match async {
                Async::Ready(()) => break,
                Async::NotReady => {},
            }
        }
    }
    circuit_creation_thread_handle.join().unwrap();
}

fn circuit_creation_thread(dir_server: String, circuit_tx: SyncSender<OpensslCircuit>) {
    let mut circ_id_tracker: IdTracker<u32> = IdTracker::new();
    let peers = match get_peer_list(&dir_server) {
        Ok(peers) => peers,
        Err(e) => {
            println!("get_peer_list failed: {:?}", e);
            return;
        }
    };
    let mut num_created_circuits = 0;
    loop {
        let circuit = match create_circuit(&dir_server, &mut circ_id_tracker, &peers) {
            Ok(circuit) => circuit,
            Err(e) => {
                println!("couldn't create new circuit: {:?}", e);
                return;
            }
        };
        num_created_circuits += 1;
        println!("created {} circuit(s) total", num_created_circuits);
        match circuit_tx.send(circuit) {
            Ok(()) => {
                println!("sent new circuit");
            }
            Err(e) => {
                println!("failed to send circuit: {:?}", e);
            }
        }
    }
}

fn create_circuit(
    dir_server: &str,
    circ_id_tracker: &mut IdTracker<u32>,
    peers: &TorPeerList
) -> Result<OpensslCircuit, Error> {
    let pre_guard_node = peers.get_guard_node()
        .ok_or(Error::new(ErrorKind::Other, "couldn't get guard node?"))?;
    let pre_interior_node = peers.get_interior_node(&[&pre_guard_node])
        .ok_or(Error::new(ErrorKind::Other, "couldn't get interior node?"))?;
    let pre_exit_node = peers.get_exit_node(&[&pre_guard_node, &pre_interior_node])
        .ok_or(Error::new(ErrorKind::Other, "couldn't get exit node?"))?;
    let microdescriptor_path = pre_guard_node.get_microdescriptor_path();
    let microdescriptor = get_microdescriptor(&dir_server, microdescriptor_path)?;
    let circ_id = circ_id_tracker.get_new_id();

    let guard_node = pre_guard_node.to_tor_peer(&microdescriptor)?;
    let addr = SocketAddr::new(IpAddr::V4(guard_node.get_ip_addr()), guard_node.get_port());
    let stream = TcpStream::connect(&addr)?;
    stream.set_nonblocking(true)?;
    let pending_tls_stream = PendingTlsOpensslImpl::new(stream)?;
    let mut tls_stream_future = TlsStreamFuture { pending_tls_stream };
    let tls_stream;
    loop {
        if let Async::Ready(ready_tls_stream) = tls_stream_future.poll()? {
            tls_stream = ready_tls_stream;
            break;
        }
    }
    let rsa_verifier = RsaVerifierOpensslImpl {};
    let rsa_signer = RsaSignerOpensslImpl::new();
    let circuit = Circuit::new(tls_stream, rsa_verifier, &rsa_signer, circ_id,
                               guard_node.get_ed25519_id_key());
    let mut circuit_open_future = CircuitOpenFuture { circuit: Some(circuit) };
    let opened_circuit;
    loop {
        if let Async::Ready(ready_opened_circuit) = circuit_open_future.poll()? {
            opened_circuit = ready_opened_circuit;
            break;
        }
    }
    let (circuit, interior_node) = pre_node_to_node(opened_circuit, pre_interior_node)?;
    let circuit = extend_circuit(circuit, interior_node)?;
    let (circuit, exit_node) = pre_node_to_node(circuit, pre_exit_node)?;
    let circuit = extend_circuit(circuit, exit_node)?;
    Ok(circuit)
}

fn pre_node_to_node(
    circuit: OpensslCircuit,
    pre_node: &PreTorPeer
) -> Result<(OpensslCircuit, TorPeer), Error> {
    let mut dir_future = CircuitDirFuture::new(circuit, pre_node.clone());
    loop {
        match dir_future.poll()? {
            Async::Ready((circuit, node)) => return Ok((circuit, node)),
            Async::NotReady => {}
        }
    }
}

fn extend_circuit(circuit: OpensslCircuit, node: TorPeer) -> Result<OpensslCircuit, Error> {
    let mut extend_future = CircuitExtendFuture { circuit: Some(circuit), node };
    loop {
        match extend_future.poll()? {
            Async::Ready(circuit) => return Ok(circuit),
            Async::NotReady => {}
        }
    }
}

struct TlsStreamFuture {
    pending_tls_stream: PendingTlsOpensslImpl<TcpStream>,
}

impl TlsStreamFuture {
    fn poll(&mut self) -> Result<Async<TlsOpensslImpl<TcpStream>>, Error> {
        loop {
            match self.pending_tls_stream.poll()? {
                Async::Ready(tls_stream) => {
                    println!("I guess we conencted?");
                    return Ok(Async::Ready(tls_stream));
                }
                Async::NotReady => {},
            }
        }
    }
}

type OpensslCircuit = Circuit<TlsOpensslImpl<TcpStream>, RsaVerifierOpensslImpl>;

struct CircuitOpenFuture {
    circuit: Option<OpensslCircuit>,
}

impl CircuitOpenFuture {
    fn poll(&mut self) -> Result<Async<OpensslCircuit>, Error> {
        let mut circuit = match self.circuit.take() {
            Some(circuit) => circuit,
            None => {
                println!("poll called with None circuit?");
                return Err(Error::new(ErrorKind::Other, "circuit should be Some here"));
            }
        };
        loop {
            match circuit.poll()? {
                Async::Ready(()) => {
                    println!("I guess the circuit's ready?");
                    return Ok(Async::Ready(circuit));
                }
                Async::NotReady => {},
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
    pre_node: PreTorPeer,
    request: Vec<u8>,
    response: Vec<u8>,
    state: CircuitDirFutureState,
}

impl CircuitDirFuture {
    fn new(circuit: OpensslCircuit, pre_node: PreTorPeer) -> CircuitDirFuture {
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

    fn poll(&mut self) -> Result<Async<(OpensslCircuit, TorPeer)>, Error> {
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
                        Async::Ready(()) => self.state = CircuitDirFutureState::RequestWriting,
                        Async::NotReady => continue,
                    }
                }
                CircuitDirFutureState::RequestWriting => {
                    match circuit.poll_stream_write(stream_id, &self.request)? {
                        Async::Ready(()) => self.state = CircuitDirFutureState::ResponseReading,
                        Async::NotReady => continue,
                    }
                }
                CircuitDirFutureState::ResponseReading => {
                    match circuit.poll_stream_read(stream_id)? {
                        Async::Ready(mut response) => {
                            // We've reached the end of what we're being sent if we get a
                            // zero-length response (although right now toroxide doesn't enforce
                            // that peers don't send us zero-length DATA cells...)
                            if response.len() == 0 {
                                let as_string = str::from_utf8(&self.response).map_err(|e| {
                                    Error::new(ErrorKind::Other, e)
                                })?;
                                let index = match as_string.find("\r\n\r\n") {
                                    Some(index) => index,
                                    None => {
                                        return Err(Error::new(ErrorKind::Other, "bad response"));
                                    }
                                };
                                let peer = self.pre_node.to_tor_peer(&as_string[index + 4..])?;
                                return Ok(Async::Ready((circuit, peer)));
                            }
                            self.response.append(&mut response);
                        }
                        Async::NotReady => {},
                    }
                }
            }
        }
    }
}

struct CircuitExtendFuture {
    circuit: Option<OpensslCircuit>,
    node: TorPeer,
}

impl CircuitExtendFuture {
    fn poll(&mut self) -> Result<Async<OpensslCircuit>, Error> {
        let mut circuit = match self.circuit.take() {
            Some(circuit) => circuit,
            None => {
                println!("poll called with None circuit?");
                return Err(Error::new(ErrorKind::Other, "circuit should be Some here"));
            }
        };
        loop {
            match circuit.poll_extend(&self.node)? {
                Async::Ready(()) => return Ok(Async::Ready(circuit)),
                Async::NotReady => {},
            }
        }
    }
}

// Synchronously fetches the peer list from the directory server.
fn get_peer_list(dir_server: &str) -> Result<TorPeerList, Error> {
    let mut stream = TcpStream::connect(dir_server)?;
    let request = "GET /tor/status-vote/current/consensus-microdesc/ HTTP/1.0\r\n\r\n";
    stream.write_all(request.as_bytes())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let index = match buf.find("\r\n\r\n") {
        Some(index) => index,
        None => return Err(Error::new(ErrorKind::Other, "bad response from directory server")),
    };
    println!("returning '{}'", &buf[index + 4..]);
    Ok(TorPeerList::new(&buf[index + 4..]))
}

// Synchronously fetches the corresponding microdescriptor from the directory server.
fn get_microdescriptor(dir_server: &str, microdescriptor_path: String) -> Result<String, Error> {
    let mut stream = TcpStream::connect(dir_server)?;
    let request = format!("GET {} HTTP/1.0\r\n\r\n", microdescriptor_path);
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let index = match response.find("\r\n\r\n") {
        Some(index) => index,
        None => return Err(Error::new(ErrorKind::Other, "bad response from directory server")),
    };
    Ok(response[index + 4..].to_owned())
}

#[derive(PartialEq)]
enum CircuitStreamState {
    Setup,
    Ready,
    Done,
}

struct CircuitStream {
    stream: TcpStream,
    stream_id: u16,
    state: CircuitStreamState,
}

impl CircuitStream {
    fn new(stream: TcpStream, stream_id: u16) -> CircuitStream {
        CircuitStream {
            stream,
            stream_id,
            state: CircuitStreamState::Setup,
        }
    }
}

struct CircuitPiper<'a> {
    circuit: OpensslCircuit,
    receiver: &'a mut Receiver<SocksPrelude>,
}

impl<'a> CircuitPiper<'a> {
    fn new(circuit: OpensslCircuit, receiver: &'a mut Receiver<SocksPrelude>) -> CircuitPiper<'a> {
        CircuitPiper { circuit, receiver }
    }

    fn socket_to_circuit(
        &mut self,
        stream: &mut CircuitStream,
    ) -> Result<Async<()>, Error> {
        let mut buf = Vec::with_capacity(498);
        buf.resize(498, 0);
        match stream.stream.read(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    return Ok(Async::Ready(()));
                }
                // TODO polling here...?
                self.circuit.poll_stream_write(stream.stream_id, &buf[..n])?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Ok(Async::NotReady),
            Err(e) => {
                println!("socket_to_circuit: {:?} (socket closed? closing stream)", e);
                return Ok(Async::Ready(()));
            }
        }
        Ok(Async::NotReady)
    }

    // I guess the contract here is if we Err'd reading from the circuit we return an Err but if we
    // Err'd writing to the stream we can just close it? (so return Ok(Async::Ready(()))
    fn circuit_to_socket(
        &mut self,
        stream: &mut CircuitStream,
    ) -> Result<Async<()>, Error> {
        match self.circuit.poll_stream_read(stream.stream_id)? {
            Async::Ready(data) => {
                if data.len() == 0 {
                    return Ok(Async::Ready(()));
                }
                // TODO polling here...?
                let mut offset = 0;
                loop {
                    match stream.stream.write(&data[offset..]) {
                        Ok(n) => {
                            offset += n;
                            if offset == data.len() {
                                break;
                            }
                        }
                        // TODO: differentiate not ready from other error?
                        Err(e) => {
                            println!("circuit_to_socket: {:?} (socket closed? closing stream)", e);
                            return Ok(Async::Ready(()));
                        }
                    }
                }
            }
            Async::NotReady => {}
        }
        Ok(Async::NotReady)
    }

    fn poll(&mut self) -> Result<Async<()>, Error> {
        let mut streams = Vec::new();
        // TODO: idea for making this not busy-loop: have an outer loop that blocking waits on
        // self.receiver, then do try_recv in the inner loop. Go back to the outer loop when
        // self.streams.len() == 0.
        loop {
            match self.receiver.try_recv() {
                Ok((stream, domain, port)) => {
                    let hostport = format!("{}:{}", domain, port);
                    println!("received connection for {}", hostport);
                    if stream.set_nonblocking(true).is_ok() {
                        let stream_id = self.circuit.open_stream(&hostport);
                        streams.push(CircuitStream::new(stream, stream_id));
                        println!("# of active streams: {}", streams.len());
                    }
                }
                // TODO: differentiate nothing there from disconnected
                Err(_) => {},
            }
            for mut stream in streams.iter_mut() {
                match stream.state {
                    CircuitStreamState::Setup => {
                        let async = match self.circuit.poll_stream_setup(stream.stream_id) {
                            Ok(async) => async,
                            Err(e) => {
                                println!("CircuitPiper stream setup error: {:?}", e);
                                return Err(e);
                            }
                        };
                        match async {
                            Async::Ready(()) => stream.state = CircuitStreamState::Ready,
                            Async::NotReady => continue,
                        }
                    }
                    CircuitStreamState::Ready => {
                        match self.socket_to_circuit(&mut stream) {
                            Ok(async) => match async {
                                Async::Ready(()) => stream.state = CircuitStreamState::Done,
                                Async::NotReady => {}
                            }
                            Err(e) => {
                                println!("socket_to_circuit: {:?}", e);
                                return Err(e);
                            }
                        }
                        // So but what about half-open kinds of things?
                        if stream.state != CircuitStreamState::Done {
                            match self.circuit_to_socket(&mut stream) {
                                Ok(async) => match async {
                                    Async::Ready(()) => stream.state = CircuitStreamState::Done,
                                    Async::NotReady => {}
                                }
                                Err(e) => {
                                    println!("circuit_to_socket: {:?}", e);
                                    return Err(e);
                                }
                            }
                        }
                    }
                    CircuitStreamState::Done => {}
                }
            }
            let len_before = streams.len();
            streams.retain(|stream| stream.state != CircuitStreamState::Done);
            let len_after = streams.len();
            if len_before != len_after {
                println!("# of active streams: {}", len_after);
            }
        }
    }
}
