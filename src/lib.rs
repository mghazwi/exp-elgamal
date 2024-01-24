
pub mod elgamal;

#[derive(Debug)]
pub enum Error {
    IncorrectInputLength(usize),
    NotPrimeOrder,
    GenericError(Box<dyn ark_std::error::Error + Send>),
}