use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::pin;
use tokio::{
    io::AsyncRead,
    net::{TcpListener, TcpStream},
};

use tokio_byteorder::BigEndian;

const VERSION_5: u8 = 0x5;

const METHOD_NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const METHOD_NO_ACCEPTABLE_METHODS: u8 = 0xff;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UPD_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAINNAME: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCEEDED: u8 = 0x00;

#[derive(Debug, Clone, PartialEq)]

struct MethodSelection {
    /// The protocol version: 0x05.
    version: u8,
    n_methods: u8,
    methods: Vec<u8>,
}

impl MethodSelection {
    async fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        buffer
            .write_u8(self.version)
            .await
            .context("writing version")?;
        buffer
            .write_u8(self.n_methods)
            .await
            .context("writing n methods")?;

        if self.methods.is_empty() || self.methods.len() > 255 {
            return Err(anyhow!("methods len must be between 1 and 255"));
        }
        tokio::io::AsyncWriteExt::write_all(&mut buffer, &self.methods)
            .await
            .context("writing methods")?;

        Ok(buffer)
    }

    async fn decode(reader: impl AsyncRead) -> Result<Self> {
        pin!(reader);

        let version = reader.read_u8().await.context("reading version")?;
        if version != VERSION_5 {
            return Err(anyhow!("only socks version 5 is supported"));
        }
        let n_methods = reader.read_u8().await.context("reading n methods")?;
        let mut methods = vec![0; n_methods as usize];
        reader
            .read_exact(&mut methods)
            .await
            .context("reading methods")?;

        Ok(Self {
            version,
            n_methods,
            methods,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct MethodSelectionResponse {
    /// The protocol version: 0x05.
    version: u8,
    method: u8,
}

impl MethodSelectionResponse {
    fn encode(&self) -> [u8; 2] {
        [self.version, self.method]
    }

    async fn decode(reader: impl AsyncRead) -> Result<Self> {
        pin!(reader);

        let version = reader.read_u8().await.context("reading version")?;
        if version != VERSION_5 {
            return Err(anyhow!("only socks version 5 is supported"));
        }

        let method = reader.read_u8().await.context("reading method")?;

        Ok(Self { version, method })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Request {
    /// The protocol version: 0x05.
    version: u8,
    /// Connect 0x01
    /// Bind 0x02
    /// UDP associate 0x03
    cmd: u8,
    /// Reserved: always 0x00
    rsv: u8,
    /// Address type of following address.
    /// IPv4 0x01
    /// DomainName 0x03
    /// IPv6 0x04
    atyp: u8,
    /// Desired destination address.
    dst_addr: Address,
    /// Desired destination port in network byte order (big endian).
    dst_port: u16,
}

impl Request {
    async fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        buffer
            .write_u8(self.version)
            .await
            .context("writing version")?;
        buffer.write_u8(self.cmd).await.context("writing cmd")?;
        buffer.write_u8(self.rsv).await.context("writing rsv")?;
        buffer.write_u8(self.atyp).await.context("writing atyp")?;

        if self.atyp == ATYP_DOMAINNAME {
            let domain_name_len = self.dst_addr.as_bytes().len();
            if domain_name_len > 256 {
                return Err(anyhow!("domain name cannot be longer than 256 bytes"));
            }

            buffer
                .write_u8(domain_name_len as u8)
                .await
                .context("writing domain name length")?;
        }

        tokio::io::AsyncWriteExt::write_all(&mut buffer, self.dst_addr.as_bytes().as_ref())
            .await
            .context("writing atyp")?;

        tokio_byteorder::AsyncWriteBytesExt::write_u16::<BigEndian>(&mut buffer, self.dst_port)
            .await
            .context("writing dst port")?;

        Ok(buffer)
    }

    async fn decode(reader: impl AsyncRead) -> Result<Self> {
        pin!(reader);

        let version = reader.read_u8().await.context("reading version")?;

        let cmd = reader.read_u8().await.context("reading cmd")?;

        let rsv = reader.read_u8().await.context("reading rsv")?;

        let atyp = reader.read_u8().await.context("reading atyp")?;

        let dst_addr = match atyp {
            ATYP_IPV4 => {
                let mut buffer = [0_u8; 4];
                reader.read_exact(&mut buffer).await?;

                Address::Ip(IpAddr::V4(
                    Ipv4Addr::try_from(buffer).context("parsing ipv4 address")?,
                ))
            }
            ATYP_IPV6 => {
                let mut buffer = [0_u8; 16];
                reader.read_exact(&mut buffer).await?;

                Address::Ip(IpAddr::V6(
                    Ipv6Addr::try_from(buffer).context("parsing ipv6 address")?,
                ))
            }
            ATYP_DOMAINNAME => {
                let domain_name_len = reader
                    .read_u8()
                    .await
                    .context("reading domain name length")?;

                let mut domain_name = vec![0_u8; domain_name_len as usize];

                reader
                    .read_exact(&mut domain_name)
                    .await
                    .context("reading domain name")?;

                Address::DomainName(
                    String::from_utf8(domain_name).context("domain name is not valid utf8")?,
                )
            }
            _ => return Err(anyhow!("unexpected atyp: {atyp}")),
        };

        let dst_port = tokio_byteorder::AsyncReadBytesExt::read_u16::<BigEndian>(&mut reader)
            .await
            .context("reading dst port")?;

        Ok(Self {
            version,
            cmd,
            rsv,
            atyp,
            dst_addr,
            dst_port,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Response {
    /// The protocol version: 0x05.
    version: u8,
    /// Reply field:
    /// 0x00 succeeded
    /// 0x01 general SOCKS server failure
    /// 0x02 connection not allowed by ruleset
    /// 0x03 network unreachable
    /// 0x04 hosted unreachable
    /// 0x05 connection refused
    /// 0x06 TTL expired
    /// 0x07 command not supported
    /// 0x08 address type not supported
    /// 0x09 to 0xff unassigned
    rep: u8,
    /// Reserved: always 0x00
    rsv: u8,
    /// Address type of following address.
    /// IPv4 0x01
    /// DomainName 0x03
    /// IPv6 0x04
    atyp: u8,
    /// Server bound address
    bind_addr: Address,
    /// Server bound port in network byte order (big endian)
    bind_port: u16,
}

impl Response {
    async fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        buffer
            .write_u8(self.version)
            .await
            .context("writing version")?;
        buffer.write_u8(self.rep).await.context("writing rep")?;
        buffer.write_u8(self.rsv).await.context("writing rsv")?;
        buffer.write_u8(self.atyp).await.context("writing atyp")?;

        tokio::io::AsyncWriteExt::write_all(&mut buffer, self.bind_addr.as_bytes().as_ref())
            .await
            .context("writing atyp")?;

        tokio_byteorder::AsyncWriteBytesExt::write_u16::<BigEndian>(&mut buffer, self.bind_port)
            .await
            .context("writing dst port")?;

        Ok(buffer)
    }

    async fn decode(reader: impl AsyncRead) -> Result<Self> {
        pin!(reader);

        let version = reader.read_u8().await.context("reading version")?;
        let rep = reader.read_u8().await.context("reading rep")?;
        let rsv = reader.read_u8().await.context("reading rsv")?;
        let atyp = reader.read_u8().await.context("reading rsv")?;

        let bind_addr = match atyp {
            ATYP_IPV4 => {
                let mut buffer = [0_u8; 4];
                reader.read_exact(&mut buffer).await?;

                Address::Ip(IpAddr::V4(
                    Ipv4Addr::try_from(buffer).context("parsing ipv4 address")?,
                ))
            }
            ATYP_IPV6 => {
                let mut buffer = [0_u8; 16];
                reader.read_exact(&mut buffer).await?;

                Address::Ip(IpAddr::V6(
                    Ipv6Addr::try_from(buffer).context("parsing ipv6 address")?,
                ))
            }
            ATYP_DOMAINNAME => {
                let domain_name_len = reader
                    .read_u8()
                    .await
                    .context("reading domain name length")?;

                let mut domain_name = vec![0_u8; domain_name_len as usize];

                reader
                    .read_exact(&mut domain_name)
                    .await
                    .context("reading domain name")?;

                Address::DomainName(
                    String::from_utf8(domain_name).context("domain name is not valid utf8")?,
                )
            }
            _ => return Err(anyhow!("unexpected atyp: {atyp}")),
        };

        let bind_port = tokio_byteorder::AsyncReadBytesExt::read_u16::<BigEndian>(&mut reader)
            .await
            .context("writing dst port")?;

        Ok(Self {
            version,
            rep,
            rsv,
            atyp,
            bind_addr,
            bind_port,
        })
    }
}

#[derive(Debug)]
pub struct Server;

impl Server {
    pub async fn start() -> Result<()> {
        let listener = TcpListener::bind("localhost:1080")
            .await
            .context("binding to port")?;

        loop {
            let (conn, _socket_addr) = listener.accept().await.context("accepting tcp conn")?;
            tokio::spawn(handle_conn(conn));
        }
    }
}

async fn handle_conn(mut conn: TcpStream) {
    if let Err(err) = handle_method_selection(&mut conn).await {
        eprintln!("in method selection: {err:?}");
        return;
    }

    let request = match Request::decode(&mut conn).await.context("reading request") {
        Err(err) => {
            eprintln!("reading request: {err:?}");
            return;
        }
        Ok(v) => v,
    };
    if request.version != VERSION_5 {
        eprintln!("only socks version 5 is supported");
        return;
    }

    match request.cmd {
        CMD_CONNECT => {
            if let Err(err) = handle_connect(conn, request).await {
                eprintln!("handling connect: {err:?}");
            }
        }
        CMD_BIND => {
            todo!()
        }
        CMD_UPD_ASSOCIATE => {
            todo!()
        }
        _ => {
            eprintln!("unexpected cmd: {}", request.cmd);
        }
    }
}

async fn handle_method_selection(mut conn: &mut TcpStream) -> Result<()> {
    let message = MethodSelection::decode(&mut conn)
        .await
        .context("reading message from tcp connection")?;

    if message.version != VERSION_5 {
        return Err(anyhow!("only socks version 5 is supported"));
    }
    if !message.methods.contains(&METHOD_NO_AUTHENTICATION_REQUIRED) {
        conn.write_all(
            &MethodSelectionResponse {
                version: VERSION_5,
                method: METHOD_NO_ACCEPTABLE_METHODS,
            }
            .encode(),
        )
        .await
        .context("writing response message")?;

        return Err(anyhow!("no authentcation is the only method supported"));
    };

    conn.write_all(
        &MethodSelectionResponse {
            version: VERSION_5,
            method: METHOD_NO_AUTHENTICATION_REQUIRED,
        }
        .encode(),
    )
    .await
    .context("writing response message")?;

    Ok(())
}

async fn handle_connect(mut conn: TcpStream, request: Request) -> Result<()> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!(
            "{}:{}",
            request.dst_addr.to_string(),
            request.dst_port
        )),
    )
    .await
    .context("connecting to dst addr")??;

    let socket_addr = stream.local_addr().context("fetching local socket addr")?;

    let response = Response {
        version: VERSION_5,
        rep: REP_SUCCEEDED,
        rsv: 0x00,
        atyp: if socket_addr.is_ipv4() {
            ATYP_IPV4
        } else {
            ATYP_IPV6
        },
        bind_addr: Address::Ip(socket_addr.ip()),
        bind_port: socket_addr.port(),
    };
    conn.write_all(&response.encode().await.context("encoding response")?)
        .await
        .context("writing request response connection")?;

    tokio::io::copy(&mut conn, &mut stream)
        .await
        .context("copying data from connection into target socket")?;

    Ok(())
}

#[derive(Debug)]
pub struct Client {
    /// Connection to socks server.
    stream: TcpStream,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    Ip(IpAddr),
    DomainName(String),
}

impl Address {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            Address::DomainName(name) => name.as_bytes().to_vec(),
            Address::Ip(ip) => match ip {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            },
        }
    }
}

impl ToString for Address {
    fn to_string(&self) -> String {
        match self {
            Address::Ip(ip) => ip.to_string(),
            Address::DomainName(name) => name.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ConnectionInput {
    pub socks_server_addr: SocketAddr,
    pub destination_addr: Address,
    pub destination_port: u16,
}

impl Client {
    pub async fn connect(input: ConnectionInput) -> Result<Self> {
        let mut stream = TcpStream::connect(input.socks_server_addr)
            .await
            .context("connecting to socks server")?;

        let message = MethodSelection {
            version: VERSION_5,
            n_methods: 1,
            methods: vec![METHOD_NO_AUTHENTICATION_REQUIRED],
        }
        .encode()
        .await
        .context("encoding message")?;

        stream
            .write_all(&message)
            .await
            .context("writing message to socket")?;

        let response = MethodSelectionResponse::decode(&mut stream)
            .await
            .context("reading method selection response")?;

        if response.method == METHOD_NO_ACCEPTABLE_METHODS {
            return Err(anyhow!(
                "the server didn't accept any of the authentcation methods"
            ));
        }

        stream
            .write_all(
                &Request {
                    version: VERSION_5,
                    cmd: CMD_CONNECT,
                    rsv: 0x0,
                    atyp: match input.destination_addr {
                        Address::Ip(socket_addr) => {
                            if socket_addr.is_ipv4() {
                                ATYP_IPV4
                            } else {
                                ATYP_IPV6
                            }
                        }

                        Address::DomainName(_) => ATYP_DOMAINNAME,
                    },
                    dst_addr: input.destination_addr,
                    dst_port: input.destination_port,
                }
                .encode()
                .await
                .context("encoding connect message")?,
            )
            .await
            .context("writing message to socket")?;

        let response = Response::decode(&mut stream)
            .await
            .context("reading response")?;

        if response.rep != REP_SUCCEEDED {
            return Err(anyhow!("request failed: rep={}", response.rep));
        }

        Ok(Self { stream })
    }

    pub async fn write(&mut self, buffer: &[u8]) -> Result<()> {
        self.stream
            .write_all(buffer)
            .await
            .context("writing to stream")
    }
}

#[cfg(test)]
#[tokio::test]
async fn client_connect_to_server() -> Result<()> {
    let dst_server = TcpListener::bind("localhost:8081").await?;
    let dst_server_addr = dst_server.local_addr()?;

    let _server_handle: tokio::task::JoinHandle<()> = tokio::spawn(async {
        if let Err(err) = Server::start().await {
            panic!("{err:?}");
        }
    });

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let mut client = Client::connect(ConnectionInput {
        socks_server_addr: "127.0.0.1:1080".parse()?,
        destination_addr: Address::Ip(dst_server_addr.ip()),
        destination_port: dst_server_addr.port(),
    })
    .await?;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let data = "hello world";
    client.write(data.as_bytes()).await?;

    let (mut stream, _socket_addr) = dst_server.accept().await?;

    let mut buffer = vec![0_u8; data.len()];
    stream.read_exact(&mut buffer).await?;

    assert_eq!(data, String::from_utf8(buffer)?);
    Ok(())
}

#[cfg(test)]
mod encode_decode_tests {
    use std::io::Cursor;

    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use tokio::runtime::Runtime;

    use super::*;

    const METHOD_GSSAPI: u8 = 0x01;
    const METHOD_USERNAME_PASSWORD: u8 = 0x02;

    static METHODS_AVAILABLE: [u8; 3] = [
        METHOD_NO_AUTHENTICATION_REQUIRED,
        METHOD_GSSAPI,
        METHOD_USERNAME_PASSWORD,
    ];

    impl Arbitrary for MethodSelection {
        fn arbitrary(g: &mut Gen) -> Self {
            // Generate value between 0 and methods.available.len().
            let n_methods = 1 + u8::arbitrary(g) % METHODS_AVAILABLE.len() as u8;

            Self {
                version: VERSION_5,
                n_methods,
                methods: METHODS_AVAILABLE
                    .into_iter()
                    .take(n_methods as usize)
                    .collect(),
            }
        }
    }

    impl Arbitrary for MethodSelectionResponse {
        fn arbitrary(g: &mut Gen) -> Self {
            // Generate value between 0 and methods_available.len() - 1.
            let index = u8::arbitrary(g) % METHODS_AVAILABLE.len() as u8;

            Self {
                version: VERSION_5,
                method: METHODS_AVAILABLE[index as usize],
            }
        }
    }

    impl Arbitrary for Request {
        fn arbitrary(g: &mut Gen) -> Self {
            const AVAILABLE_CMDS: [u8; 3] = [CMD_CONNECT, CMD_BIND, CMD_UPD_ASSOCIATE];

            let cmd = g.choose(&AVAILABLE_CMDS).cloned().unwrap();

            // let atyp = g
            //     .choose(&[ATYP_IPV4, ATYP_IPV6, ATYP_DOMAINNAME])
            //     .cloned()
            //     .unwrap();

            let atyp = ATYP_IPV4;

            let dst_addr = match atyp {
                ATYP_IPV4 => Address::Ip(IpAddr::V4(Ipv4Addr::arbitrary(g))),
                ATYP_IPV6 => Address::Ip(IpAddr::V6(Ipv6Addr::arbitrary(g))),
                ATYP_DOMAINNAME => Address::DomainName("localhost".to_owned()),
                _ => unreachable!(),
            };

            let dst_port = u16::arbitrary(g);

            Self {
                version: VERSION_5,
                cmd,
                rsv: 0x0,
                atyp,
                dst_addr,
                dst_port,
            }
        }
    }

    impl Arbitrary for Response {
        fn arbitrary(g: &mut Gen) -> Self {
            const AVAILABLE_REPS: [u8; 10] =
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

            let rep = g.choose(&AVAILABLE_REPS).cloned().unwrap();

            // let atyp = g
            //     .choose(&[ATYP_IPV4, ATYP_IPV6, ATYP_DOMAINNAME])
            //     .cloned()
            //     .unwrap();

            let atyp = ATYP_IPV4;

            let bind_addr = match atyp {
                ATYP_IPV4 => Address::Ip(IpAddr::V4(Ipv4Addr::arbitrary(g))),
                ATYP_IPV6 => Address::Ip(IpAddr::V6(Ipv6Addr::arbitrary(g))),
                ATYP_DOMAINNAME => Address::DomainName("localhost".to_owned()),
                _ => unreachable!(),
            };

            let bind_port = u16::arbitrary(g);

            Self {
                version: VERSION_5,
                rep,
                rsv: 0x0,
                atyp,
                bind_addr,
                bind_port,
            }
        }
    }

    #[quickcheck]
    fn encode_decode_method_selection(message: MethodSelection) -> Result<()> {
        Runtime::new()?.block_on(async {
            let encoded = message.encode().await?;
            assert_eq!(
                message,
                MethodSelection::decode(Cursor::new(encoded)).await?
            );
            Ok(())
        })
    }

    #[quickcheck]
    fn encode_decode_method_selection_response(message: MethodSelectionResponse) -> Result<()> {
        Runtime::new()?.block_on(async {
            let encoded = message.encode();
            assert_eq!(
                message,
                MethodSelectionResponse::decode(Cursor::new(encoded)).await?
            );
            Ok(())
        })
    }

    #[quickcheck]
    fn encode_decode_method_request(message: Request) -> Result<()> {
        Runtime::new()?.block_on(async {
            let encoded = message.encode().await?;
            assert_eq!(message, Request::decode(Cursor::new(encoded)).await?);
            Ok(())
        })
    }

    #[quickcheck]
    fn encode_decode_method_response(message: Response) -> Result<()> {
        Runtime::new()?.block_on(async {
            let encoded = message.encode().await?;
            assert_eq!(message, Response::decode(Cursor::new(encoded)).await?);
            Ok(())
        })
    }
}
