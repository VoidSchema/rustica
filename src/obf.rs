//! Runtime decoder for the constants emitted by build.rs.

include!(concat!(env!("OUT_DIR"), "/strings.rs"));

type Const = (&'static [u8], &'static [u8]);

fn decode(t: Const) -> Vec<u8> {
    let (encoded, keystream) = t;
    let mut out = Vec::with_capacity(encoded.len());
    for (i, b) in encoded.iter().enumerate() {
        out.push(b ^ keystream[i % keystream.len()]);
    }
    out
}

pub fn s(t: Const) -> String {
    String::from_utf8_lossy(&decode(t)).into_owned()
}

pub fn num(t: Const) -> u64 {
    s(t).trim().parse().unwrap_or(0)
}

pub fn flag(t: Const) -> bool {
    matches!(
        s(t).trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
