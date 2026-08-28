use hbb_common::{
    config,
    protobuf::Message as PbMessage,
    protos::rendezvous::{
        rendezvous_message, PunchHoleRequest, RegisterPeer, RendezvousMessage, TestNatRequest,
    },
    tcp::FramedStream,
    udp::FramedSocket,
};

const SERVER: &str = "201.24.52.171";
const OLD_RUSTDESK_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";

fn main() {
    let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
    rt.block_on(run());
}

async fn tcp_roundtrip(label: &str, port: i32, msg: RendezvousMessage) {
    let addr = format!("{}:{}", SERVER, port);
    match FramedStream::new(&addr, None, 5000).await {
        Err(e) => println!("  {:<34} TCP не подключился: {}", label, e),
        Ok(mut s) => {
            if let Err(e) = s.send(&msg).await {
                println!("  {:<34} не отправилось: {}", label, e);
                return;
            }
            // сервер может первым прислать KeyExchange — пропускаем его
            for _ in 0..2 {
                match s.next_timeout(5000).await {
                    None => {
                        println!("  {:<34} ответа нет за 5с", label);
                        return;
                    }
                    Some(Err(e)) => {
                        println!("  {:<34} ошибка: {}", label, e);
                        return;
                    }
                    Some(Ok(b)) => match RendezvousMessage::parse_from_bytes(&b) {
                        Err(e) => {
                            println!("  {:<34} не разобралось: {}", label, e);
                            return;
                        }
                        Ok(m) => match m.union {
                            Some(rendezvous_message::Union::KeyExchange(_)) => continue,
                            Some(rendezvous_message::Union::TestNatResponse(r)) => {
                                println!("  {:<34} TestNatResponse, видимый порт = {}", label, r.port);
                                return;
                            }
                            Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
                                println!("  {:<34} failure = {:?}", label, r.failure.enum_value());
                                return;
                            }
                            other => {
                                println!("  {:<34} {:?}", label, other);
                                return;
                            }
                        },
                    },
                }
            }
        }
    }
}

fn punch_msg(key: &str) -> RendezvousMessage {
    let mut m = RendezvousMessage::new();
    m.set_punch_hole_request(PunchHoleRequest {
        id: "987654321".to_owned(),
        licence_key: key.to_owned(),
        version: "1.4.9".to_owned(),
        ..Default::default()
    });
    m
}

fn nat_msg() -> RendezvousMessage {
    let mut m = RendezvousMessage::new();
    m.set_test_nat_request(TestNatRequest { serial: 0, ..Default::default() });
    m
}

async fn run() {
    println!("Сервер из config: {:?}", config::RENDEZVOUS_SERVERS);
    println!("Ключ из config:   {}\n", config::RS_PUB_KEY);

    println!("[1] TCP — NAT-тест (то, что реально шлёт клиент по TCP)");
    tcp_roundtrip("порт 21116", config::RENDEZVOUS_PORT, nat_msg()).await;
    tcp_roundtrip("порт 21115", config::RENDEZVOUS_PORT - 1, nat_msg()).await;

    println!("\n[2] UDP 21116 — регистрация");
    let listen = config::Config::get_any_listen_addr(true);
    match FramedSocket::new(listen).await {
        Err(e) => println!("  сокет не поднялся: {}", e),
        Ok(mut sock) => {
            let mut m = RendezvousMessage::new();
            m.set_register_peer(RegisterPeer { id: "987654321".to_owned(), serial: 0, ..Default::default() });
            let _ = sock.send(&m, format!("{}:{}", SERVER, config::RENDEZVOUS_PORT)).await;
            match sock.next_timeout(5000).await {
                None => println!("  ответа нет за 5с"),
                Some(Err(e)) => println!("  ошибка: {}", e),
                Some(Ok((b, from))) => match RendezvousMessage::parse_from_bytes(&b) {
                    Err(e) => println!("  не разобралось: {}", e),
                    Ok(m) => println!("  от {:?}: {:?}", from, m.union),
                },
            }
        }
    }

    println!("\n[3] TCP 21116 — punch_hole, проверка ключа");
    tcp_roundtrip("ваш ключ", config::RENDEZVOUS_PORT, punch_msg(config::RS_PUB_KEY)).await;
    tcp_roundtrip("контроль: старый ключ RustDesk", config::RENDEZVOUS_PORT, punch_msg(OLD_RUSTDESK_KEY)).await;
    tcp_roundtrip("контроль: мусор", config::RENDEZVOUS_PORT, punch_msg("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")).await;
    tcp_roundtrip("контроль: пустой ключ", config::RENDEZVOUS_PORT, punch_msg("")).await;
}
