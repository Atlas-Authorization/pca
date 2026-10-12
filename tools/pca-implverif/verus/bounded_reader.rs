// Verus proof (ALL usize values, unbounded) of the index arithmetic of sdks/stark-pca BoundedReader and the
// check_batch_opening length checks. This is the code that, in the stock winterfell SliceReader, computed
// `pos + num_bytes` and wrapped for a length near usize::MAX.
// SCOPE: transliteration of the arithmetic (pos, data.len(), requested len); the byte contents are irrelevant to it.
// The real code is additionally exercised by Kani (kani-stark-pca) with symbolic bytes for data.len() <= bound.
use vstd::prelude::*;
verus! {

pub struct Reader { pub data_len: usize, pub pos: usize }
impl Reader {
    pub open spec fn inv(&self) -> bool { self.pos <= self.data_len }

    pub fn remaining(&self) -> (r: usize) requires self.inv(), ensures r == self.data_len - self.pos { self.data_len - self.pos }

    // check_eor: Err iff num_bytes > remaining. Cannot overflow (no addition).
    pub fn check_eor(&self, num_bytes: usize) -> (ok: bool)
        requires self.inv(),
        ensures ok <==> num_bytes <= self.data_len - self.pos,
    { !(num_bytes > self.remaining()) }

    // read_slice: on success the slice [pos, pos+len) is inside data and pos+len does not wrap.
    pub fn read_slice(&mut self, len: usize) -> (ok: bool)
        requires old(self).inv(),
        ensures
            final(self).inv(), final(self).data_len == old(self).data_len,
            ok <==> len <= old(self).data_len - old(self).pos,
            ok ==> final(self).pos as int == old(self).pos as int + len as int && final(self).pos <= final(self).data_len,
            !ok ==> final(self).pos == old(self).pos,
    {
        if !self.check_eor(len) { return false; }
        self.pos = self.pos + len;      // no overflow: len <= data_len - pos
        true
    }

    pub fn read_u8(&mut self) -> (ok: bool)
        requires old(self).inv(),
        ensures final(self).inv(), ok <==> old(self).pos < old(self).data_len, ok ==> final(self).pos == old(self).pos + 1,
    {
        if self.pos < self.data_len { self.pos = self.pos + 1; true } else { false }
    }

    // read_many pre-check (allocation guard): every element is >= 1 byte, so count <= remaining.
    pub fn read_many_ok(&self, num_elements: usize) -> (ok: bool)
        requires self.inv(),
        ensures ok ==> num_elements <= self.data_len - self.pos,   // Vec::with_capacity(num_elements) is bounded by input size
    { self.check_eor(num_elements) }
}

// check_batch_opening inner step: digests.checked_mul(32).filter(|b| b <= remaining) then read_slice(bytes).
pub fn digest_step(r: &mut Reader, digests: usize) -> (ok: bool)
    requires old(r).inv(),
    ensures
        final(r).inv(),
        ok <==> digests as int * 32 <= old(r).data_len as int - old(r).pos as int,   // exact, no wrap for ANY usize digests
        ok ==> final(r).pos as int == old(r).pos as int + digests as int * 32,
{
    let rem = r.remaining();
    match digests.checked_mul(32) {
        Some(b) => { if b <= rem { r.read_slice(b) } else { false } }
        None => false,
    }
}

fn main() {}
}
