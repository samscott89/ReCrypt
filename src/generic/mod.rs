//! Generic constructions of updatable encryption from building blocks

mod hybrid;
mod naive;
mod null;

pub use self::naive::{KemDem, Naive};
pub use self::hybrid::{Kss, ReCrypt};
