use digest::Digest;
use either::Either;

/// Trait for types that can feed their content into a digest hasher.
pub trait Digestible {
    fn digest_update<D: Digest>(&self, hasher: &mut D);
}

macro_rules! impl_digestible_numeric {
    ($($t:ty),*) => {
        $(impl Digestible for $t {
            fn digest_update<D: Digest>(&self, hasher: &mut D) {
                hasher.update(&self.to_le_bytes());
            }
        })*
    };
}

impl_digestible_numeric!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64, usize, isize);

impl Digestible for bool {
    fn digest_update<D: Digest>(&self, hasher: &mut D) {
        (*self as u8).digest_update(hasher);
    }
}

impl <T: Digestible> Digestible for Box<T> {
    fn digest_update<D: Digest>(&self, hasher: &mut D) {
        (**self).digest_update(hasher);
    }
}

impl<const N: usize> Digestible for [u8; N] {
    fn digest_update<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.as_slice());
    }
}

impl<S: digest::array::ArraySize> Digestible for digest::array::Array<u8, S> {
    fn digest_update<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.as_slice());
    }
}

impl<L: Digestible, R: Digestible> Digestible for Either<L, R> {
    fn digest_update<D: digest::Digest>(&self, hasher: &mut D) {
        match self {
            Either::Left(l)  => { hasher.update(&[0u8]); l.digest_update(hasher); }
            Either::Right(r) => { hasher.update(&[1u8]); r.digest_update(hasher); }
        }
    }
}