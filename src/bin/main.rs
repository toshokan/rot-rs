use typenum::consts::*;

fn main() {
    use rot::Rotate;
    
    let s = "abcdefghijklmnopqrstuvwxyz";
    let r = s.bytes()
        .rotate_by::<P26>()
        .map(|r| r.rotate_by::<Z0>())
        .map(Into::into)
        .collect();
    // Note that it's always safe to do this!
    // Rotations are verified at compile-time to be valid UTF-8.
    let s = unsafe {String::from_utf8_unchecked(r)};
    eprintln!("{}", s);
}
