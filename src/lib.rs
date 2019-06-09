//! # Rot
//! Strongly-typed ascii character rotations in the style of Caesar/Rot/Vigenère ciphers.
//! This is only meant to be some fun with type-level integers in Rust.
//! *Please do not use this as an encryption scheme* as it is *laughably* weak.

use typenum::{Integer};
use typenum::consts::{Z0, P26};
use typenum::type_operators::{Same};
use typenum::operator_aliases::{Sum};
use std::marker::PhantomData;
use std::ops::{Add, Rem};

use std::fmt;

/// A wrapper over Ascii `u8` which rotates alphabetic characters by `N`.
/// This is essentially a per-character Caesar cipher with a shift of `N`.
/// A collection of this type may also be used to implement a strongly-typed Vigenère cipher.
/// An interesting characteristic is that this type can only be converted back to
/// a raw `u8` when it has been rotated back into place (i.e `N % 26 == 0`),
/// otherwise it is a compile-time type error to do so.
/// It is also type-parameterized over the rotation length to prevent
/// partial/improper ciphers at compile-time.
/// This makes it impossible to use a byte rotated right by 12 when a type contract
/// requires a byte rotated left by 13, for example.
///
/// # Examples
/// ## Rotate some `u8` bytes by 7 positions to the right.
/// ```
/// use rot::{Rotate, RotU8};
/// use typenum::consts::P7;
/// let s = "a b c";
/// let r : Vec<RotU8<P7>> = s.bytes().rotate_by::<P7>().collect();
/// ```
///
/// ## Try to incorrectly read a rotated byte
/// ```compile_fail
/// use rot::{Rotate, RotU8};
/// use typenum::consts::P1;
/// let c = 'a' as u8;
/// let rotated: RotU8<P1> = c.into();
/// let contents: u8 = rotated.into();  // This will fail to type check!
/// ```
///
/// ## Perform no-op rotations
/// ```
/// use rot::{Rotate, RotU8};
/// use typenum::consts::{Z0, P26};
/// let c = 'a' as u8;
/// let rotated_by_zero: RotU8<Z0> = c.into();
/// let rotated_by_26: RotU8<P26> = c.into();
/// let contents_0: u8 = rotated_by_zero.into();  // This works, `c` wasn't rotated.
/// assert_eq!(contents_0, 'a' as u8);
/// // This works, `c` was rotated back to the start point.
/// let contents_26: u8 = rotated_by_26.into();
/// assert_eq!(contents_26, 'a' as u8);
/// ```
///
/// ## Type safe signatures
/// ```
/// use typenum::{Integer};
/// use typenum::consts::{Z0, P1, N1};
/// use rot::RotU8;
///
/// // This function cannot secretly rotate the byte (unless it rotates it back!)
/// // This would be useful in a trait definition to enforce a stronger contract.
/// fn should_not_rotate<N: Integer>(rc: RotU8<N>) -> RotU8<N> {
///     unimplemented!();
/// }
/// ```
/// 
/// ```compile_fail
/// use typenum::{Integer};
/// use typenum::consts::{Z0, P1, N1};
/// use rot::RotU8;
///
/// fn evil_function<N: Integer>(rc: RotU8<N>) -> RotU8<N> {
///     rc.rotate_by::<P1>() // Compile-time error!
///     // ^ this has type RotU8<N+1>
/// }
/// ```
/// 
/// ```
/// use typenum::{Integer};
/// use typenum::consts::{Z0, P1, N1};
/// use rot::RotU8;
///
/// fn not_so_evil_function<N: Integer>(rc: RotU8<N>) -> RotU8<N> {
///     rc.rotate_by::<Z0>() // Works fine! Adding zero (or a multiple of 26) doesn't rotate.
/// }
/// ````
#[derive(Clone, Copy)]
pub struct RotU8<N: Integer>(u8, PhantomData<N>);

impl<N: Integer> fmt::Display for RotU8<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RotU8<{}>({})", N::to_i8(), self.0 as char)
    }
}

impl<N: Integer> fmt::Debug for RotU8<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RotU8<{}>({})", N::to_i8(), &self.0)
    }
}

impl<N> RotU8<N>
where N: Integer {
    /// Create a new `RotU8<N>` from a pre-rotated character byte.
    fn new(rotated: u8) -> Self {
        Self(rotated, PhantomData)
    }

    /// Get the raw underlying `u8` in rotated form.
    /// ```
    /// use typenum::consts::P1;
    /// use rot::RotU8;
    /// 
    /// let rotated : RotU8<P1> = ('a' as u8).into();
    /// assert_eq!(rotated.as_raw(), 'a' as u8 + 1);
    /// ```
    pub fn as_raw(&self) -> u8 {
        self.0
    }

    /// Wrap an offset character byte (in the positive _or_ negative directions)
    /// and ensure it is in the range `[0, 26)`
    fn wrapping_rotate_mod26(c: i8) -> u8 {
        ((((c + N::to_i8()) % 26) + 26) % 26) as u8
    }

    /// Rotate a character relative to a start point for a 26 character range.
    /// If rotating a lowercase ascii letter, the range starts at `'a'`,
    /// otherwise it starts at `'A'`.
    fn rotate_relative(c: u8, zero_point: u8) -> u8 {
        let offset = c - zero_point;
        Self::wrapping_rotate_mod26(offset as i8) + zero_point
    }

    /// Rotate the raw ascii character `ch` `N` positions,
    /// _if is an alphabetic character_,
    /// otherwise do not change it.
    /// If `N` is positive, this performs a wrapped shift to the right.
    /// If `N` is negative, this performs a wrapped shift to the left.
    /// A zero value for `N` is identity.
    ///
    /// ```
    /// use typenum::consts::{N2, P1, Z0};
    /// use rot::RotU8;
    /// 
    /// assert_eq!(Into::<RotU8<P1>>::into('a' as u8).as_raw(), 'b' as u8);
    /// assert_eq!(Into::<RotU8<N2>>::into('a' as u8).as_raw(), 'y' as u8);
    /// assert_eq!(Into::<RotU8<Z0>>::into('a' as u8).as_raw(), 'a' as u8);
    /// assert_eq!(Into::<RotU8<N2>>::into('7' as u8).as_raw(), '7' as u8);
    /// ```
    fn rotate(ch: u8) -> u8 {
        let c = ch as i8;
        match ch as char {
            'A' ... 'Z' => {
                Self::rotate_relative(c as u8, 'A' as u8)
            }
            'a' ... 'z' => {
                Self::rotate_relative(c as u8, 'a' as u8)
            },
            _ => ch
        }
    }

    /// Chain a rotation by `N` with a rotation by `M`.
    /// ```
    /// use typenum::consts::{P1, P2, P3, N1, N4};
    /// use rot::RotU8;
    ///
    /// let rotate_by_one: RotU8<P1> = ('a' as u8).into();
    /// let rotate_by_three: RotU8<P3> = rotate_by_one.rotate_by::<P2>();
    /// assert_eq!(rotate_by_three.as_raw(), 'd' as u8);
    /// let rotate_back: RotU8<N1> = rotate_by_three.rotate_by::<N4>();
    /// assert_eq!(rotate_back.as_raw(), 'z' as u8);
    /// ```
    pub fn rotate_by<M>(self) -> RotU8<Sum<M, N>>
    where
        M: Add<N> + Integer,
        <M as Add<N>>::Output: Integer
    {
        let c = self.0;
        let rotated = RotU8::<M>::rotate(c);
        RotU8::new(rotated)
    }
}

impl<N> From<u8> for RotU8<N>
where
    N: Integer
{
    fn from(source: u8) -> Self {
        let rotated = Self::rotate(source);
        Self::new(rotated)
    }
}

/// Wraps a raw character/byte iterator and rotates each item.
pub struct RotIter<N: Integer, I: Iterator> {
    iter: I,
    _p: PhantomData<N>
}

/// Rotate `Self::Item` by `N`.
pub trait Rotate
where
    Self: Iterator + Sized
{
    fn rotate_by<N: Integer>(self) -> RotIter<N, Self>;
}

impl<I> Rotate for I
where
    I: Iterator<Item = u8>
{
    fn rotate_by<N: Integer>(self) -> RotIter<N, Self> {
        RotIter {
            iter: self,
            _p: PhantomData
        }
    }
}

impl<N: Integer, I: Iterator<Item = u8>> Iterator for RotIter<N, I> {
    type Item = RotU8<N>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(From::from)
    }
}

impl<'a, N> Into<u8> for RotU8<N>
where
    N: Rem<P26> + Integer,
    <N as Rem<P26>>::Output: Integer + Same<Z0>,
{
    fn into(self) -> u8 {
        self.0
    }
}
