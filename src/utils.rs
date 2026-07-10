//! This module contains miscellaneous operations used by this library.
//! In particular, it re-exports [`Allocator`] and [`Box`] from either
//! the standard library or `allocator_api2`, depending on how this
//! crate is compiled.

#[cfg(not(feature = "nightly"))]
pub use allocator_api2::{boxed::Box, alloc::Allocator};
#[cfg(feature = "nightly")]
pub use std::{boxed::Box, alloc::Allocator};
use std::fmt::Write;

/// Given a mutable input slice and a list of `indices`, return a vector of mutable references for each indexed element
///
/// SAFETY: Caller must ensure that each index in the `indices` array is in-bounds for the input slice and that it contains no duplicates.
pub unsafe fn pick_mut_unchecked<'a, T>(arr: &'a mut [T], indices: &[usize]) -> Vec<&'a mut T> {
    let ptr = arr.as_mut_ptr();
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

/// Evaluate an expression, log it via `tracing`, and return it unchanged.
///
/// Forms:
///   trace_val!(expr)                              // DEBUG, records `value = ?expr`
///   trace_val!(LEVEL, expr)                       // same, at LEVEL
///   trace_val!(name = expr, "fmt")                // DEBUG; format may use {name} + scope vars
///   trace_val!(LEVEL, name = expr, "fmt", ...)    // same, at LEVEL, with extra args/fields
///
/// The two-argument form `trace_val!(a, b)` treats `a` as the level and `b` as the value.
#[macro_export]
macro_rules! trace_val {
    ($expr:expr $(,)?) => {{
        let value = $expr;
        ::tracing::event!(::tracing::Level::DEBUG, ?value);
        value
    }};
    ($name:ident = $expr:expr, $($fmt:tt)+) => {{
        let $name = $expr;
        ::tracing::event!(::tracing::Level::DEBUG, $($fmt)+);
        $name
    }};
    ($lvl:expr, $expr:expr $(,)?) => {{
        let value = $expr;
        ::tracing::event!($lvl, ?value);
        value
    }};
    ($lvl:expr, $name:ident = $expr:expr, $($fmt:tt)+) => {{
        let $name = $expr;
        ::tracing::event!($lvl, $($fmt)+);
        $name
    }};
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