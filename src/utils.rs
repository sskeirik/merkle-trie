//! Memory and debugging utility functions.
//! 
//! This module contains miscellaneous operations used by this library.
//! In particular, it re-exports [`Allocator`] and [`Box`] from either
//! the standard library or `allocator_api2`, depending on how this
//! crate is compiled.
#[cfg(not(feature = "std_allocator_api"))]
pub use allocator_api2::{boxed::Box, alloc::Allocator};
#[cfg(feature = "std_allocator_api")]
pub use std::{boxed::Box, alloc::Allocator};
use std::fmt::Write;

/// A shared reference to an [`Option`] that must be non-`None`
pub struct NonNone<'a,T>(&'a Option<T>);
impl<'a,T> NonNone<'a,T> {
    pub fn new(opt: &'a Option<T>) -> Option<Self> {
        if opt.is_none() {
            return None
        }
        Some(Self(opt))
    }

    /// Return a shared reference to the inner value
    pub fn get(&self) -> &'a T {
        // SAFETY: by construction
        let opt_ref = self.0.as_ref();
        unsafe { opt_ref.unwrap_unchecked() }
    }

    /// Consume the [`NonNone`] and obtain its contents
    pub fn into_inner(self) -> &'a Option<T> {
        self.0
    }
}

/// A mutable reference to an [`Option`] that must be non-`None`
pub struct NonNoneMut<'a,T>(&'a mut Option<T>);
impl<'a,T> NonNoneMut<'a,T> {
    pub fn new(opt: &'a mut Option<T>) -> Option<Self> {
        if opt.is_none() {
            return None
        }
        Some(Self(opt))
    }

    /// Return a shared reference to the inner value as a reborrow
    pub fn reborrow_ref(&self) -> &T {
        // SAFETY: by construction
        let opt_ref = self.0.as_ref();
        unsafe { opt_ref.unwrap_unchecked() }
    }

    /// Return a mutable reference to the inner value as a reborrow
    pub fn reborrow_mut(&mut self) -> &mut T {
        // SAFETY: by construction
        let opt_ref = self.0.as_mut();
        unsafe { opt_ref.unwrap_unchecked() }
    }

    /// Consume the [`NonNoneMut`] and obtain its contents
    pub fn into_inner(self) -> &'a mut Option<T> {
        self.0
    }

    /// Consume the [`NonNoneMut`] and obtain a mutable reference its inner value
    pub fn into_mut(self) -> &'a mut T {
        let opt_mut = self.0.as_mut();
        // SAFETY: by construction
        unsafe { opt_mut.unwrap_unchecked() }
    }
}

/// Given a mutable input slice and a list of `indices`, return a vector of mutable references for each indexed element
///
/// # SAFETY
/// 
/// Caller must ensure that each index in the `indices` array is in-bounds for the input slice and that it contains no duplicates.
pub unsafe fn pick_mut_unchecked<'a, T>(arr: &'a mut [T], indices: &[usize]) -> Vec<&'a mut T> {
    let ptr = arr.as_mut_ptr();
    // SAFETY: by assumption
    indices.iter().map(|&i| unsafe { &mut *ptr.add(i) }).collect()
}

/// Given a byte slice and an allocator, create a new allocator-owned copy of that slice
pub fn copy_slice_into_box<A: Allocator>(src: &[u8], alloc: A) -> Box<[u8], A> {
    let mut boxed = Box::new_uninit_slice_in(src.len(), alloc);
    // SAFETY: we immediately initialize all elements by copying from src
    unsafe {
        std::ptr::copy_nonoverlapping(
            src.as_ptr(),
            boxed.as_mut_ptr() as *mut u8,
            src.len(),
        );
        boxed.assume_init()
    }
}

/// Print a byte string as ASCII characters
/// 
/// Non-printable characters are represented via hexadecimal escapes.
pub fn to_ascii(bytes: &[u8]) -> String {
    bytes.iter()
         .flat_map(|&b| std::ascii::escape_default(b))
         .map(|c| c as char)
         .collect()
}

/// Print a byte string as hexadecimal pairs
pub fn to_hex<const MSB: bool>(slice: &[u8]) -> String {
    let mut buf = String::with_capacity(3);
    let mut s = String::with_capacity(slice.len() * 2);
    for i in slice {
        if MSB {
            if write!(s, "{:02x} ", *i).is_err() {
                s.clear();
                s.push_str("<err>");
                return s;
            };
        } else {
            if write!(buf, "{:02x} ", *i).is_err() {
                s.clear();
                s.push_str("<err>");
                return s;
            }
            s.extend(buf.chars().rev());
            buf.clear();
        }
    }
    s.trim().to_string()
}

/// Print a byte string as binary octects
pub fn to_bin<const MSB: bool>(slice: &[u8]) -> String {
    let mut buf = String::with_capacity(9);
    let mut s = String::with_capacity(slice.len() * 9);
    for i in slice {
        if MSB {
            if write!(s, "{:08b} ", *i).is_err() {
                s.clear();
                s.push_str("<err>");
                return s;
            };
        } else {
            if write!(buf, "{:08b} ", *i).is_err() {
                s.clear();
                s.push_str("<err>");
                return s;
            }
            s.extend(buf.chars().rev());
            buf.clear();
        }
    }
    s.trim().to_string()
}