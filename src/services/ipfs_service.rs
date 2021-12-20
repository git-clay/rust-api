use ipfsapi::IpfsApi;

pub fn fetch_hash(hash: &str) {
    //"QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u"
    let api = IpfsApi::new("127.0.0.1", 5001);

    let bytes = api.cat(hash).unwrap();
    let data = String::from_utf8(bytes.collect()).unwrap();

    println!("{}", data);
}
