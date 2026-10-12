// shared by the Miri decoder drivers (included with include!): a SMALL sweep plus targeted boundary positions.
//   offsets(len): the first 8 bytes, the last 8 bytes, and NSAMPLE (env, default 8) evenly spaced positions.
//   length_prefix_offsets(b, w): offsets whose w-byte little-endian value is a plausible length prefix (1..=len), capped at 24.
#[allow(dead_code)]
fn offsets(len: usize) -> Vec<usize> {
    let ns: usize = std::env::var("NSAMPLE").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
    let mut v: Vec<usize> = (0..len.min(8)).collect();
    v.extend(len.saturating_sub(8)..len);
    if len > 0 { for k in 0..ns { v.push(k * len / ns); } }
    v.sort(); v.dedup(); v
}
#[allow(dead_code)]
fn length_prefix_offsets(b: &[u8], w: usize) -> Vec<usize> {
    let mut v = vec![];
    let mut o = 0;
    while o + w <= b.len() && v.len() < 8 {
        let mut x: u64 = 0; for i in 0..w { x |= (b[o + i] as u64) << (8 * i); }
        if x >= 1 && (x as usize) <= b.len() { v.push(o); o += w; } else { o += 1; }
    }
    v
}
#[allow(dead_code)]
const BOUNDARY_BYTES: [u8; 3] = [0x00, 0x80, 0xff];
