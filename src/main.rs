use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;

async fn handle(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    eprintln!(": {}", req.uri());
    let split = req.uri().to_string();
    let split = split.split("/").collect::<Vec<_>>().split_off(1);
    //    let params = url::Url::parse(&req.uri().to_string()).unwrap();
    //let params = req.uri().query_pairs().collect::<Vec<_>>();
    //eprintln!(" P: {:?}", params);

    let fingerprint = split[0];
    let op = split[1];

    if op == "check" {
        for card in openpgp_card_pcsc::PcscClient::cards().unwrap_or(Vec::new()) {
            let mut app = openpgp_card::CardApp::from(card);
            let ard = app.get_application_related_data().unwrap();
            let fingerprints = ard.get_fingerprints().unwrap();

            eprintln!(" FPS: {:?}", fingerprints);
            if fingerprints.decryption().unwrap().to_string() == fingerprint {
                let body = hyper::body::to_bytes(req.into_body()).await?;
		let pin = String::from_utf8_lossy(&body);
                if app.verify_pw1(&pin).is_err() {
                    return Ok(Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Default::default())
                        .unwrap());
                }

                let algo = ard.get_algorithm_attributes(openpgp_card::KeyType::Decryption).unwrap();

                eprintln!(" ALGO: {:?}", algo);
                let mut resp = Response::default();

		let op = match algo {
		    openpgp_card::algorithm::Algo::Rsa(..) => "rsa-decrypt",
		    openpgp_card::algorithm::Algo::Ecc(..) => "derive",
		    _ => panic!("Unsupported algo"),
		};

		let hint = if let openpgp_card::algorithm::Algo::Ecc(attrs) = algo {
		    match attrs.curve() {
			openpgp_card::algorithm::Curve::Cv25519 => "Cv25519",
			_ => "-",
		    }
		} else {
		    ""
		};

                resp.headers_mut().insert(
                    "Location",
                    hyper::header::HeaderValue::from_str(
                        &http::Uri::builder()
                            .scheme("http")
                            .authority("localhost:3000")
                            .path_and_query(format!("/{}/{}/{}/{}", ard.get_application_id().unwrap().ident(), op, hint, pin))
                            .build()
                            .unwrap()
                            .to_string(),
                    )
                    .unwrap(),
                );

                return Ok(resp);
            }
            //let algo = algo.get_by_keytype(openpgp_card::KeyType::Signing);

            //eprintln!(" FPS: {:?}", fingerprints);
        }
        Ok(Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(Default::default())
            .unwrap())

    /*
    let mut app = openpgp_card::CardApp::from(
        openpgp_card_pcsc::PcscClient::open_by_ident(&card_ident).unwrap(),
    );
    let body = hyper::body::to_bytes(req.into_body()).await?;
    if app.verify_pw1(&String::from_utf8_lossy(&body)).is_ok() {
        Ok(Response::new(Body::from("OK")))
    } else {
        Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Default::default())
            .unwrap())
    }*/
    } else if op == "rsa-decrypt" {
        let card_ident = split[2];

        let mut app = openpgp_card::CardApp::from(
            openpgp_card_pcsc::PcscClient::open_by_ident(&card_ident).unwrap(),
        );
        let body = hyper::body::to_bytes(req.into_body()).await?;
        let dm = openpgp_card::crypto_data::Cryptogram::RSA(&body);
        if let Ok(dec) = app.decipher(dm) {
            Ok(Response::new(Body::from(dec)))
        } else {
            Ok(Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .body(Default::default())
                .unwrap())
        }
    } else if op == "derive" {
        let card_ident = split[0];

        let curve = split[2];
	let pin = split[3];
        let mut app = openpgp_card::CardApp::from(
            openpgp_card_pcsc::PcscClient::open_by_ident(&card_ident).unwrap(),
        );

                if app.verify_pw1(&pin).is_err() {
                    return Ok(Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Default::default())
                        .unwrap());
                }


	let body = hyper::body::to_bytes(req.into_body()).await?;

        let dm = if curve == "Cv25519" {
            // Ephemeral key without header byte 0x40
            openpgp_card::crypto_data::Cryptogram::ECDH(&body[1..])
        } else {
            // NIST curves: ephemeral key with header byte
            openpgp_card::crypto_data::Cryptogram::ECDH(&body)
        };

        // Decryption operation on the card
        let mut dec = if let Ok(dec) = app.decipher(dm) {
            dec
        } else {
            return Ok(Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .body(Default::default())
                .unwrap());
        };

        // Specifically handle return value format like Gnuk's
        // (Gnuk returns a leading '0x04' byte and
        // an additional 32 trailing bytes)
        if curve == "NistP256" && dec.len() == 65 {
            assert_eq!(dec[0], 0x04, "unexpected shape of decrypted data");

            // see Gnuk src/call-ec.c:82
            dec = dec[1..33].to_vec();
        }
        Ok(Response::new(Body::from(dec)))
    } else {
        Ok(Response::new(Body::from(format!(
            "Hello World: {:?}",
            split
        ))))
    }
}

#[tokio::main]
async fn main() {
    // Construct our SocketAddr to listen on...
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // And a MakeService to handle each connection...
    let make_service = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle)) });

    // Then bind and serve...
    let server = Server::bind(&addr).serve(make_service);

    // And run forever...
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
