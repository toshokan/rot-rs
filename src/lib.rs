use typenum::{Integer};
use typenum::consts::{Z0, P26};
use typenum::type_operators::{Same};
use typenum::operator_aliases::{Sum};
use std::marker::PhantomData;
use std::ops::{Add, Rem};

use std::fmt;

#[derive(Clone, Copy)]
pub struct RotU8<N: Integer>(u8, PhantomData<N>);

impl<N: Integer> fmt::Display for RotU8<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RotU8<{}>({})", N::to_i8(), self.0 as char)
    }
}

impl<N: Integer> fmt::Debug for RotU8<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RotU8<{}>({})", N::to_i8(), self.0 as char)
    }
}

impl<N> RotU8<N>
where N: Integer {
    fn new(rotated: u8) -> Self {
        Self(rotated, PhantomData)
    }
    
    fn wrapping_rotate_mod26(c: i8) -> u8 {
        ((((c + N::to_i8()) % 26) + 26) % 26) as u8
    }
    
    fn rotate_relative(c: u8, zero_point: u8) -> u8 {
        let offset = c - zero_point;
        Self::wrapping_rotate_mod26(offset as i8) + zero_point
    }
    
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

pub struct RotIter<N: Integer, I: Iterator> {
    iter: I,
    _p: PhantomData<N>
}

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
