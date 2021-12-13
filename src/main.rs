use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
//use hyperlocal::UnixServerExt;
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;
use std::convert::Infallible;
use std::net::SocketAddr;

const SCHEME: &str = "unix";

async fn handle(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    eprintln!(": {}", req.uri());
    if let Some(auth) = req.headers().get("authorization") {
        eprintln!("  -> with auth: {:?}", auth);
    }
    let host = String::from_utf8_lossy(req.headers().get("host").unwrap().as_bytes()).to_string();

    let split = req.uri().to_string();
    let split = split.split('?').collect::<Vec<_>>()[0];
    let split = split.split('/').collect::<Vec<_>>().split_off(1);
    //    let params = url::Url::parse(&req.uri().to_string()).unwrap();
    //let params = req.uri().query_pairs().collect::<Vec<_>>();
    //eprintln!(" P: {:?}", params);

    let fingerprint = split[0];
    if split.len() == 1 {
        if fingerprint.is_empty() {
            let body = std::fs::read_to_string("index.html").unwrap();
            return Ok(Response::new(Body::from(body)));
        } else if fingerprint == "favicon.ico" {
            return Ok(Response::new(Body::default()));
        } else if fingerprint == "keys" {
            let mut buf = String::new();
            for card in openpgp_card_pcsc::PcscClient::cards().unwrap_or_default() {
                let mut app = openpgp_card::CardApp::from(card);
                let ard = app.get_application_related_data().unwrap();
                let fingerprints = ard.get_fingerprints().unwrap();
                let card_id = ard.get_application_id().unwrap().ident();
                if let Some(fpr) = fingerprints.signature() {
                    buf += &format!("{} # {} S\n", fpr, card_id);
                }
                if let Some(fpr) = fingerprints.decryption() {
                    buf += &format!("{} # {} E\n", fpr, card_id);
                }
                if let Some(fpr) = fingerprints.authentication() {
                    buf += &format!("{} # {} A\n", fpr, card_id);
                }
            }
            return Ok(Response::new(Body::from(buf)));
        }
        //return Ok(Response::

        for card in openpgp_card_pcsc::PcscClient::cards().unwrap_or_default() {
            let mut app = openpgp_card::CardApp::from(card);
            let ard = app.get_application_related_data().unwrap();
            let fingerprints = ard.get_fingerprints().unwrap();
            eprintln!("FPRS: {:?}", fingerprints);

            if fingerprints
                .decryption()
                .map_or("".into(), |fp| fp.to_string())
                == fingerprint
            {
                eprintln!("FOUND!");
                let body = hyper::body::to_bytes(req.into_body()).await?;
                let pin = String::from_utf8_lossy(&body);
                if app.verify_pw1(&pin).is_err() {
                    return Ok(Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Default::default())
                        .unwrap());
                }

                let algo = ard
                    .get_algorithm_attributes(openpgp_card::KeyType::Decryption)
                    .unwrap();

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
                            .scheme(SCHEME)
                            .authority(host)
                            .path_and_query(format!(
                                "/{}/{}/{}/{}",
                                ard.get_application_id().unwrap().ident(),
                                op,
                                hint,
                                pin
                            ))
                            .build()
                            .unwrap()
                            .to_string(),
                    )
                    .unwrap(),
                );

                return Ok(resp);
            } else if fingerprints
                .signature()
                .map_or("".into(), |fp| fp.to_string())
                == fingerprint
            {
                let body = hyper::body::to_bytes(req.into_body()).await?;
                let pin = String::from_utf8_lossy(&body);
                if app.verify_pw1_for_signing(&pin).is_err() {
                    return Ok(Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Default::default())
                        .unwrap());
                }

                let algo = ard
                    .get_algorithm_attributes(openpgp_card::KeyType::Signing)
                    .unwrap();

                let mut resp = Response::default();

                let op = match algo {
                    openpgp_card::algorithm::Algo::Rsa(..) => "rsa-sign",
                    openpgp_card::algorithm::Algo::Ecc(..) => "ecc-sign",
                    _ => panic!("Unsupported algo"),
                };

                let hint = if let openpgp_card::algorithm::Algo::Ecc(attrs) = algo {
                    match attrs.curve() {
                        openpgp_card::algorithm::Curve::Ed25519 => "Ed25519",
                        _ => "-",
                    }
                } else {
                    ""
                };

                resp.headers_mut().insert(
                    "Location",
                    hyper::header::HeaderValue::from_str(
                        &http::Uri::builder()
                            .scheme(SCHEME)
                            .authority(host)
                            .path_and_query(format!(
                                "/{}/{}/{}/{}/",
                                ard.get_application_id().unwrap().ident(),
                                op,
                                hint,
                                pin
                            ))
                            .build()
                            .unwrap()
                            .to_string(),
                    )
                    .unwrap(),
                );

                return Ok(resp);
            } else if fingerprints
                .authentication()
                .map_or("".into(), |fp| fp.to_string())
                == fingerprint
            {
                let body = hyper::body::to_bytes(req.into_body()).await?;
                let pin = String::from_utf8_lossy(&body);
                if app.verify_pw1(&pin).is_err() {
                    return Ok(Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Default::default())
                        .unwrap());
                }

                let algo = ard
                    .get_algorithm_attributes(openpgp_card::KeyType::Signing)
                    .unwrap();

                let mut resp = Response::default();

                let op = match algo {
                    openpgp_card::algorithm::Algo::Rsa(..) => "rsa-auth",
                    openpgp_card::algorithm::Algo::Ecc(..) => "ecc-auth",
                    _ => panic!("Unsupported algo"),
                };

                let hint = if let openpgp_card::algorithm::Algo::Ecc(attrs) = algo {
                    match attrs.curve() {
                        openpgp_card::algorithm::Curve::Ed25519 => "Ed25519",
                        _ => "-",
                    }
                } else {
                    ""
                };

                resp.headers_mut().insert(
                    "Location",
                    hyper::header::HeaderValue::from_str(
                        &http::Uri::builder()
                            .scheme(SCHEME)
                            .authority(host)
                            .path_and_query(format!(
                                "/{}/{}/{}/{}/",
                                ard.get_application_id().unwrap().ident(),
                                op,
                                hint,
                                pin
                            ))
                            .build()
                            .unwrap()
                            .to_string(),
                    )
                    .unwrap(),
                );

                return Ok(resp);
            }
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
    } else {
        let op = split[1];

        if op == "public" {
            let fingerprint = split[0];
            for card in openpgp_card_pcsc::PcscClient::cards().unwrap_or_default() {
                let mut app = openpgp_card::CardApp::from(card);
                let ard = app.get_application_related_data().unwrap();
                let fingerprints = ard.get_fingerprints().unwrap();
                let key_type = if fingerprints.signature().unwrap().to_string() == fingerprint {
                    Some(KeyType::Signing)
                } else if fingerprints.decryption().unwrap().to_string() == fingerprint {
                    Some(KeyType::Decryption)
                } else if fingerprints.authentication().unwrap().to_string() == fingerprint {
                    Some(KeyType::Authentication)
                } else {
                    None
                };
                if let Some(key_type) = key_type {
                    let pub_key = app.get_pub_key(key_type).unwrap();
                    eprintln!("PK: {:#?}", pub_key);
                    let (content_type, data) = match pub_key {
                        PublicKeyMaterial::R(ref rsa) => {
                            ("application/vnd.pks.public.rsa.modulus", rsa.n().to_vec())
                        }
                        PublicKeyMaterial::E(ref ecc) => (
                            "application/vnd.pks.public.ed25519.compressed",
                            ecc.data().to_vec(),
                        ),
                        _ => panic!("Unsupported key type"),
                    };
                    let mut resp = Response::builder();
                    resp = resp.header("Content-Type", content_type);

                    return Ok(resp.body(Body::from(data)).unwrap());
                }
            }
            Ok(Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(Default::default())
                .unwrap())
        } else if op == "rsa-decrypt" {
            let card_ident = split[2];

            let mut app = openpgp_card::CardApp::from(
                openpgp_card_pcsc::PcscClient::open_by_ident(card_ident).unwrap(),
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
                openpgp_card_pcsc::PcscClient::open_by_ident(card_ident).unwrap(),
            );

            if app.verify_pw1(pin).is_err() {
                return Ok(Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(Default::default())
                    .unwrap());
            }

            let body = hyper::body::to_bytes(req.into_body()).await?;
            eprintln!("BODY = {}", hex::encode(&body));

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
        } else if op == "rsa-sign" {
            let card_ident = split[0];

            let pin = split[3];
            let mut app = openpgp_card::CardApp::from(
                openpgp_card_pcsc::PcscClient::open_by_ident(card_ident).unwrap(),
            );

            if app.verify_pw1_for_signing(pin).is_err() {
                return Ok(Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(Default::default())
                    .unwrap());
            }

            use openpgp_card::crypto_data::Hash;
            use std::convert::TryInto;

            let query = req
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/vnd.pks.digest.sha512")
                .to_string();
            let digest = hyper::body::to_bytes(req.into_body()).await?.to_vec();

            let hash = if query == "application/vnd.pks.digest.sha256" {
                Hash::SHA256(digest.try_into().unwrap())
            } else if query == "application/vnd.pks.digest.sha384" {
                Hash::SHA384(digest.try_into().unwrap())
            } else if query == "application/vnd.pks.digest.sha512" {
                Hash::SHA512(digest.try_into().unwrap())
            } else {
                panic!("Unsupported digest.");
            };

            let sig = app.signature_for_hash(hash).unwrap();

            Ok(Response::builder()
                .header("Content-Type", "application/vnd.pks.signature.rsa")
                .body(Body::from(sig))
                .unwrap())
        } else if op == "ecc-sign" {
            let card_ident = split[0];

            let eddsa = split[2] == "Ed25519";

            let pin = split[3];
            let mut app = openpgp_card::CardApp::from(
                openpgp_card_pcsc::PcscClient::open_by_ident(card_ident).unwrap(),
            );
            if app.verify_pw1_for_signing(pin).is_err() {
                return Ok(Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(Default::default())
                    .unwrap());
            }

            use openpgp_card::crypto_data::Hash;
            //use std::convert::TryInto;

            //let query = req.uri().query().unwrap().to_string();
            let digest = hyper::body::to_bytes(req.into_body()).await?.to_vec();

            let hash = if eddsa {
                Hash::EdDSA(&digest)
            } else {
                Hash::ECDSA(&digest)
            };

            let sig = app.signature_for_hash(hash).unwrap();
            Ok(Response::builder()
                .header("Content-Type", "application/vnd.pks.signature.eddsa.rs")
                .body(Body::from(sig))
                .unwrap())
        } else if op == "ecc-auth" {
            let card_ident = split[0];

            let pin = split[3];
            let mut app = openpgp_card::CardApp::from(
                openpgp_card_pcsc::PcscClient::open_by_ident(card_ident).unwrap(),
            );
            if app.verify_pw1(pin).is_err() {
                return Ok(Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(Default::default())
                    .unwrap());
            }

            //use std::convert::TryInto;

            //let query = req.uri().query().unwrap().to_string();
            let digest = hyper::body::to_bytes(req.into_body()).await?.to_vec();
            /*
                    let hash = if eddsa {
                        Hash::EdDSA(&digest)
                    } else {
                        Hash::ECDSA(&digest)
                    };
            */
            let sig = app.internal_authenticate(digest).unwrap();

            Ok(Response::new(Body::from(sig)))
        } else {
            Ok(Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(Default::default())
                .unwrap())
        }
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
    //let server = Server::bind_unix("/var/run/user/1000/pks").unwrap().serve(make_service);

    // And run forever...
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
