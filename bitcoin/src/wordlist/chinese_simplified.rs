use crate::wordlist::BitcoinWordlist;
use gyu_model::{wordlist::bip39::CHINESE_SIMPLIFIED, wordlist::Wordlist};k

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChinessSimplified;

impl Wordlist for ChinessSimplified{}

impl BitcoinWordlist for ChinessSimplified {
    const WORDLIST: &'static str = CHINESE_SIMPLIFIED;
}
