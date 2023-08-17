// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses.
//!
//! Support for ordinary base58 Bitcoin addresses and private keys.
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! use bitcoin::network::constants::Network;
//! use bitcoin::util::address::Address;
//! use bitcoin::{Blockchain, PublicKey};
//! use bitcoin::secp256k1::Secp256k1;
//! use bitcoin::secp256k1::rand::thread_rng;
//!
//! // Generate random key pair.
//! let s = Secp256k1::new();
//! let public_key = PublicKey::new(s.generate_keypair(&mut thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin, Blockchain::Bitcoin);
//! ```

use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;

use bech32;
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};

use crate::blockdata::constants::{
    BITCOIN_PUBKEY_ADDRESS_PREFIX_MAIN, BITCOIN_PUBKEY_ADDRESS_PREFIX_TEST,
    BITCOIN_SCRIPT_ADDRESS_PREFIX_MAIN, BITCOIN_SCRIPT_ADDRESS_PREFIX_TEST,
    DOGECOIN_PUBKEY_ADDRESS_PREFIX_MAIN, DOGECOIN_PUBKEY_ADDRESS_PREFIX_TEST,
    DOGECOIN_SCRIPT_ADDRESS_PREFIX_MAIN, DOGECOIN_SCRIPT_ADDRESS_PREFIX_TEST,
    LITECOIN_PUBKEY_ADDRESS_PREFIX_MAIN, LITECOIN_PUBKEY_ADDRESS_PREFIX_TEST,
    LITECOIN_SCRIPT_ADDRESS_PREFIX_MAIN, LITECOIN_SCRIPT_ADDRESS_PREFIX_TEST,
    STRATIS_PUBKEY_ADDRESS_PREFIX_MAIN, STRATIS_PUBKEY_ADDRESS_PREFIX_TEST,
    STRATIS_SCRIPT_ADDRESS_PREFIX_MAIN, STRATIS_SCRIPT_ADDRESS_PREFIX_TEST,
    RAVENCOIN_PUBKEY_ADDRESS_PREFIX_MAIN, RAVENCOIN_PUBKEY_ADDRESS_PREFIX_TEST,
    RAVENCOIN_SCRIPT_ADDRESS_PREFIX_MAIN, RAVENCOIN_SCRIPT_ADDRESS_PREFIX_TEST,
    MAX_SCRIPT_ELEMENT_SIZE,
};
use crate::blockdata::script::Instruction;
use crate::blockdata::{opcodes, script};
use crate::error::ParseIntError;
use crate::hash_types::{PubkeyHash, ScriptHash};
use crate::hashes::{sha256, Hash, HashEngine};
use crate::internal_macros::{serde_string_impl, write_err};
use crate::network::constants::Network;
use crate::prelude::*;
use crate::util::base58;
use crate::util::key::PublicKey;
use crate::util::schnorr::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::util::taproot::TapBranchHash;

/// Address error.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error.
    Base58(base58::Error),
    /// Bech32 encoding error.
    Bech32(bech32::Error),
    /// The bech32 payload was empty.
    EmptyBech32Payload,
    /// The wrong checksum algorithm was used. See BIP-0350.
    InvalidBech32Variant {
        /// Bech32 variant that is required by the used Witness version.
        expected: bech32::Variant,
        /// The actual Bech32 variant encoded in the address representation.
        found: bech32::Variant,
    },
    /// Script version must be 0 to 16 inclusive.
    InvalidWitnessVersion(u8),
    /// Unable to parse witness version from string.
    UnparsableWitnessVersion(ParseIntError),
    /// Bitcoin script opcode does not match any known witness version, the script is malformed.
    MalformedWitnessVersion,
    /// The witness program must be between 2 and 40 bytes in length.
    InvalidWitnessProgramLength(usize),
    /// A v0 witness program must be either of length 20 or 32.
    InvalidSegwitV0ProgramLength(usize),
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
    /// Address size more than 520 bytes is not allowed.
    ExcessiveScriptSize,
    /// Script is not a p2pkh, p2sh or witness program.
    UnrecognizedScript,
    /// Address type is either invalid or not supported in rust-bitcoin.
    UnknownAddressType(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write_err!(f, "base58 address encoding error"; e),
            Error::Bech32(ref e) => write_err!(f, "bech32 address encoding error"; e),
            Error::EmptyBech32Payload => write!(f, "the bech32 payload was empty"),
            Error::InvalidBech32Variant { expected, found } => write!(f, "invalid bech32 checksum variant found {:?} when {:?} was expected", found, expected),
            Error::InvalidWitnessVersion(v) => write!(f, "invalid witness script version: {}", v),
            Error::UnparsableWitnessVersion(ref e) => write_err!(f, "incorrect format of a witness version byte"; e),
            Error::MalformedWitnessVersion => f.write_str("bitcoin script opcode does not match any known witness version, the script is malformed"),
            Error::InvalidWitnessProgramLength(l) => write!(f, "the witness program must be between 2 and 40 bytes in length: length={}", l),
            Error::InvalidSegwitV0ProgramLength(l) => write!(f, "a v0 witness program must be either of length 20 or 32 bytes: length={}", l),
            Error::UncompressedPubkey => write!(f, "an uncompressed pubkey was used where it is not allowed"),
            Error::ExcessiveScriptSize => write!(f, "script size exceed 520 bytes"),
            Error::UnrecognizedScript => write!(f, "script is not a p2pkh, p2sh or witness program"),
            Error::UnknownAddressType(ref s) => write!(f, "unknown address type: '{}' is either invalid or not supported in rust-bitcoin", s),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Base58(e) => Some(e),
            Bech32(e) => Some(e),
            UnparsableWitnessVersion(e) => Some(e),
            EmptyBech32Payload
            | InvalidBech32Variant { .. }
            | InvalidWitnessVersion(_)
            | MalformedWitnessVersion
            | InvalidWitnessProgramLength(_)
            | InvalidSegwitV0ProgramLength(_)
            | UncompressedPubkey
            | ExcessiveScriptSize
            | UnrecognizedScript
            | UnknownAddressType(_) => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error { Error::Base58(e) }
}

#[doc(hidden)]
impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error { Error::Bech32(e) }
}

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to taproot.
    P2tr,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2wsh => "p2wsh",
            AddressType::P2tr => "p2tr",
        })
    }
}

impl FromStr for AddressType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2wsh" => Ok(AddressType::P2wsh),
            "p2tr" => Ok(AddressType::P2tr),
            _ => Err(Error::UnknownAddressType(s.to_owned())),
        }
    }
}

/// Version of the witness program.
///
/// Helps limit possible versions of the witness according to the specification. If a plain `u8`
/// type was used instead it would mean that the version may be > 16, which would be incorrect.
///
/// First byte of `scriptPubkey` in transaction output for transactions starting with opcodes
/// ranging from 0 to 16 (inclusive).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
pub enum WitnessVersion {
    /// Initial version of witness program. Used for P2WPKH and P2WPK outputs
    V0 = 0,
    /// Version of witness program used for Taproot P2TR outputs.
    V1 = 1,
    /// Future (unsupported) version of witness program.
    V2 = 2,
    /// Future (unsupported) version of witness program.
    V3 = 3,
    /// Future (unsupported) version of witness program.
    V4 = 4,
    /// Future (unsupported) version of witness program.
    V5 = 5,
    /// Future (unsupported) version of witness program.
    V6 = 6,
    /// Future (unsupported) version of witness program.
    V7 = 7,
    /// Future (unsupported) version of witness program.
    V8 = 8,
    /// Future (unsupported) version of witness program.
    V9 = 9,
    /// Future (unsupported) version of witness program.
    V10 = 10,
    /// Future (unsupported) version of witness program.
    V11 = 11,
    /// Future (unsupported) version of witness program.
    V12 = 12,
    /// Future (unsupported) version of witness program.
    V13 = 13,
    /// Future (unsupported) version of witness program.
    V14 = 14,
    /// Future (unsupported) version of witness program.
    V15 = 15,
    /// Future (unsupported) version of witness program.
    V16 = 16,
}

/// Prints [`WitnessVersion`] number (from 0 to 16) as integer, without
/// any prefix or suffix.
impl fmt::Display for WitnessVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", *self as u8) }
}

impl FromStr for WitnessVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version: u8 = crate::parse::int(s).map_err(Error::UnparsableWitnessVersion)?;
        WitnessVersion::try_from(version)
    }
}

impl WitnessVersion {
    /// Converts 5-bit unsigned integer value matching single symbol from Bech32(m) address encoding
    /// ([`bech32::u5`]) into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program.
    ///
    /// # Errors
    /// If the integer does not correspond to any witness version, errors with
    /// [`Error::InvalidWitnessVersion`].
    #[deprecated(since = "0.29.0", note = "use try_from instead")]
    pub fn from_u5(value: bech32::u5) -> Result<Self, Error> { Self::try_from(value) }

    /// Converts an 8-bit unsigned integer value into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program.
    ///
    /// # Errors
    /// If the integer does not correspond to any witness version, errors with
    /// [`Error::InvalidWitnessVersion`].
    #[deprecated(since = "0.29.0", note = "use try_from instead")]
    pub fn from_num(no: u8) -> Result<Self, Error> { Self::try_from(no) }

    /// Converts bitcoin script opcode into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program (for opcodes in range of `OP_0`..`OP_16`).
    ///
    /// # Errors
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::MalformedWitnessVersion`].
    #[deprecated(since = "0.29.0", note = "use try_from instead")]
    pub fn from_opcode(opcode: opcodes::All) -> Result<Self, Error> { Self::try_from(opcode) }

    /// Converts bitcoin script [`Instruction`] (parsed opcode) into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program for [`Instruction::Op`] and [`Instruction::PushBytes`] with
    /// byte value within `1..=16` range.
    ///
    /// # Errors
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::MalformedWitnessVersion`] for the rest of opcodes.
    #[deprecated(since = "0.29.0", note = "use try_from instead")]
    pub fn from_instruction(instruction: Instruction) -> Result<Self, Error> {
        Self::try_from(instruction)
    }

    /// Returns integer version number representation for a given [`WitnessVersion`] value.
    ///
    /// NB: this is not the same as an integer representation of the opcode signifying witness
    /// version in bitcoin script. Thus, there is no function to directly convert witness version
    /// into a byte since the conversion requires context (bitcoin script or just a version number).
    #[deprecated(since = "0.29.0", note = "use to_num instead")]
    pub fn into_num(self) -> u8 { self.to_num() }

    /// Returns integer version number representation for a given [`WitnessVersion`] value.
    ///
    /// NB: this is not the same as an integer representation of the opcode signifying witness
    /// version in bitcoin script. Thus, there is no function to directly convert witness version
    /// into a byte since the conversion requires context (bitcoin script or just a version number).
    pub fn to_num(self) -> u8 { self as u8 }

    /// Determines the checksum variant. See BIP-0350 for specification.
    pub fn bech32_variant(&self) -> bech32::Variant {
        match self {
            WitnessVersion::V0 => bech32::Variant::Bech32,
            _ => bech32::Variant::Bech32m,
        }
    }
}

impl TryFrom<bech32::u5> for WitnessVersion {
    type Error = Error;

    /// Converts 5-bit unsigned integer value matching single symbol from Bech32(m) address encoding
    /// ([`bech32::u5`]) into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program.
    ///
    /// # Errors
    /// If the integer does not correspond to any witness version, errors with
    /// [`Error::InvalidWitnessVersion`].
    fn try_from(value: bech32::u5) -> Result<Self, Self::Error> { Self::try_from(value.to_u8()) }
}

impl TryFrom<u8> for WitnessVersion {
    type Error = Error;

    /// Converts an 8-bit unsigned integer value into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program.
    ///
    /// # Errors
    /// If the integer does not correspond to any witness version, errors with
    /// [`Error::InvalidWitnessVersion`].
    fn try_from(no: u8) -> Result<Self, Self::Error> {
        use WitnessVersion::*;

        Ok(match no {
            0 => V0,
            1 => V1,
            2 => V2,
            3 => V3,
            4 => V4,
            5 => V5,
            6 => V6,
            7 => V7,
            8 => V8,
            9 => V9,
            10 => V10,
            11 => V11,
            12 => V12,
            13 => V13,
            14 => V14,
            15 => V15,
            16 => V16,
            wrong => return Err(Error::InvalidWitnessVersion(wrong)),
        })
    }
}

impl TryFrom<opcodes::All> for WitnessVersion {
    type Error = Error;

    /// Converts bitcoin script opcode into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program (for opcodes in range of `OP_0`..`OP_16`).
    ///
    /// # Errors
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::MalformedWitnessVersion`].
    fn try_from(opcode: opcodes::All) -> Result<Self, Self::Error> {
        match opcode.to_u8() {
            0 => Ok(WitnessVersion::V0),
            version
                if version >= opcodes::all::OP_PUSHNUM_1.to_u8()
                    && version <= opcodes::all::OP_PUSHNUM_16.to_u8() =>
                WitnessVersion::try_from(version - opcodes::all::OP_PUSHNUM_1.to_u8() + 1),
            _ => Err(Error::MalformedWitnessVersion),
        }
    }
}

impl<'a> TryFrom<Instruction<'a>> for WitnessVersion {
    type Error = Error;

    /// Converts bitcoin script [`Instruction`] (parsed opcode) into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program for [`Instruction::Op`] and [`Instruction::PushBytes`] with
    /// byte value within `1..=16` range.
    ///
    /// # Errors
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::MalformedWitnessVersion`] for the rest of opcodes.
    fn try_from(instruction: Instruction) -> Result<Self, Self::Error> {
        match instruction {
            Instruction::Op(op) => WitnessVersion::try_from(op),
            Instruction::PushBytes(bytes) if bytes.is_empty() => Ok(WitnessVersion::V0),
            Instruction::PushBytes(_) => Err(Error::MalformedWitnessVersion),
        }
    }
}

impl From<WitnessVersion> for bech32::u5 {
    /// Converts [`WitnessVersion`] instance into corresponding Bech32(m) u5-value ([`bech32::u5`]).
    fn from(version: WitnessVersion) -> Self {
        bech32::u5::try_from_u8(version.to_num()).expect("WitnessVersion must be 0..=16")
    }
}

impl From<WitnessVersion> for opcodes::All {
    /// Converts [`WitnessVersion`] instance into corresponding Bitcoin scriptopcode (`OP_0`..`OP_16`).
    fn from(version: WitnessVersion) -> opcodes::All {
        match version {
            WitnessVersion::V0 => opcodes::all::OP_PUSHBYTES_0,
            no => opcodes::All::from(opcodes::all::OP_PUSHNUM_1.to_u8() + no.to_num() - 1),
        }
    }
}

/// The method used to produce an address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Payload {
    /// P2PKH address.
    PubkeyHash(PubkeyHash),
    /// P2SH address.
    ScriptHash(ScriptHash),
    /// Segwit address.
    WitnessProgram {
        /// The witness program version.
        version: WitnessVersion,
        /// The witness program.
        program: Vec<u8>,
    },
}

impl Payload {
    /// Constructs a [Payload] from an output script (`scriptPubkey`).
    pub fn from_script(script: &script::Script) -> Result<Payload, Error> {
        Ok(if script.is_p2pkh() {
            let mut hash_inner = [0u8; 20];
            hash_inner.copy_from_slice(&script.as_bytes()[3..23]);
            Payload::PubkeyHash(PubkeyHash::from_inner(hash_inner))
        } else if script.is_p2sh() {
            let mut hash_inner = [0u8; 20];
            hash_inner.copy_from_slice(&script.as_bytes()[2..22]);
            Payload::ScriptHash(ScriptHash::from_inner(hash_inner))
        } else if script.is_witness_program() {
            if script.witness_version() == Some(WitnessVersion::V0)
                && !(script.is_v0_p2wpkh() || script.is_v0_p2wsh())
            {
                return Err(Error::InvalidSegwitV0ProgramLength(script.len() - 2));
            }

            Payload::WitnessProgram {
                version: WitnessVersion::try_from(opcodes::All::from(script[0]))?,
                program: script[2..].to_vec(),
            }
        } else {
            return Err(Error::UnrecognizedScript);
        })
    }

    /// Generates a script pubkey spending to this [Payload].
    pub fn script_pubkey(&self) -> script::Script {
        match *self {
            Payload::PubkeyHash(ref hash) => script::Script::new_p2pkh(hash),
            Payload::ScriptHash(ref hash) => script::Script::new_p2sh(hash),
            Payload::WitnessProgram { version, program: ref prog } =>
                script::Script::new_witness_program(version, prog),
        }
    }

    /// Creates a pay to (compressed) public key hash payload from a public key
    #[inline]
    pub fn p2pkh(pk: &PublicKey) -> Payload { Payload::PubkeyHash(pk.pubkey_hash()) }

    /// Creates a pay to script hash P2SH payload from a script
    #[inline]
    pub fn p2sh(script: &script::Script) -> Result<Payload, Error> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(Error::ExcessiveScriptSize);
        }
        Ok(Payload::ScriptHash(script.script_hash()))
    }

    /// Create a witness pay to public key payload from a public key
    pub fn p2wpkh(pk: &PublicKey) -> Result<Payload, Error> {
        Ok(Payload::WitnessProgram {
            version: WitnessVersion::V0,
            program: pk.wpubkey_hash().ok_or(Error::UncompressedPubkey)?.to_vec(),
        })
    }

    /// Create a pay to script payload that embeds a witness pay to public key
    pub fn p2shwpkh(pk: &PublicKey) -> Result<Payload, Error> {
        let builder = script::Builder::new()
            .push_int(0)
            .push_slice(&pk.wpubkey_hash().ok_or(Error::UncompressedPubkey)?);

        Ok(Payload::ScriptHash(builder.into_script().script_hash()))
    }

    /// Create a witness pay to script hash payload.
    pub fn p2wsh(script: &script::Script) -> Payload {
        Payload::WitnessProgram {
            version: WitnessVersion::V0,
            program: script.wscript_hash().to_vec(),
        }
    }

    /// Create a pay to script payload that embeds a witness pay to script hash address
    pub fn p2shwsh(script: &script::Script) -> Payload {
        let ws =
            script::Builder::new().push_int(0).push_slice(&script.wscript_hash()).into_script();

        Payload::ScriptHash(ws.script_hash())
    }

    /// Create a pay to taproot payload from untweaked key
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapBranchHash>,
    ) -> Payload {
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        Payload::WitnessProgram {
            version: WitnessVersion::V1,
            program: output_key.to_inner().serialize().to_vec(),
        }
    }

    /// Create a pay to taproot payload from a pre-tweaked output key.
    ///
    /// This method is not recommended for use and [Payload::p2tr()] should be used where possible.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey) -> Payload {
        Payload::WitnessProgram {
            version: WitnessVersion::V1,
            program: output_key.to_inner().serialize().to_vec(),
        }
    }

    /// Returns a byte slice of the payload
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Payload::ScriptHash(hash) => hash,
            Payload::PubkeyHash(hash) => hash,
            Payload::WitnessProgram { program, .. } => program,
        }
    }
}

/// A utility struct to encode an address payload with the given parameters.
/// This is a low-level utility struct. Consider using `Address` instead.
pub struct AddressEncoding<'a> {
    /// The address payload to encode.
    pub payload: &'a Payload,
    /// base58 version byte for p2pkh payloads (e.g. 0x00 for "1..." addresses).
    pub p2pkh_prefix: u8,
    /// base58 version byte for p2sh payloads (e.g. 0x05 for "3..." addresses).
    pub p2sh_prefix: u8,
    /// hrp used in bech32 addresss (e.g. "bc" for "bc1..." addresses).
    pub bech32_hrp: &'a str,
}

impl<'a> fmt::Display for AddressEncoding<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2pkh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2sh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::WitnessProgram { version, program: prog } => {
                let mut upper_writer;
                let writer = if fmt.alternate() {
                    upper_writer = UpperWriter(fmt);
                    &mut upper_writer as &mut dyn fmt::Write
                } else {
                    fmt as &mut dyn fmt::Write
                };
                let mut bech32_writer =
                    bech32::Bech32Writer::new(self.bech32_hrp, version.bech32_variant(), writer)?;
                bech32::WriteBase32::write_u5(&mut bech32_writer, (*version).into())?;
                bech32::ToBase32::write_base32(&prog, &mut bech32_writer)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Supported blockchains.
pub enum Blockchain {
    /// The Bitcoin blockchain.
    Bitcoin,
    /// The Dogecoin blockchain.
    Dogecoin,
    /// The Litecoin blockchain.
    Litecoin,
    /// The Stratis blockchain.
    Stratis,
    /// The Ravencoin blockchain.
    Ravencoin,
}

impl fmt::Display for Blockchain {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Blockchain::Bitcoin => "Bitcoin",
            Blockchain::Dogecoin => "Dogecoin",
            Blockchain::Litecoin => "Litecoin",
            Blockchain::Stratis => "Stratis",
            Blockchain::Ravencoin => "Ravencoin",
        };
        write!(fmt, "{}", s)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
/// Prefix data required to serialize an address.
// This is tightly coupled with the Network, if someone mutates an address by
// changing the network without updating the prefix bad things will happen.
pub enum Prefix {
    /// Pubkey hash prefix byte.
    Pubkey(u8),
    /// Script hash prefix byte.
    Script(u8),
    /// Segwit prefix characters e.g., "bc"
    Segwit(String),
}

impl Prefix {
    /// Create a prefix for a pubkey hash address given a prefix byte.
    pub fn pubkey(b: u8) -> Self { Prefix::Pubkey(b) }

    /// Create a prefix for a script hash address given a prefix byte.
    pub fn script(b: u8) -> Self { Prefix::Script(b) }

    /// Create a prefix for a segwit address given a bech32 prefix string.
    pub fn segwit(hrp: &str) -> Self { Prefix::Segwit(hrp.to_string()) }

    /// Create the correct prefix based on `payload`, coupled with `network` and `chain`.
    pub fn from_payload(payload: &Payload, network: Network, chain: Blockchain) -> Self {
        match payload {
            Payload::PubkeyHash(_) => {
                let b = match (network, chain) {
                    (Network::Bitcoin, Blockchain::Bitcoin) => BITCOIN_PUBKEY_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Bitcoin) => BITCOIN_PUBKEY_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Dogecoin) => DOGECOIN_PUBKEY_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Dogecoin) => DOGECOIN_PUBKEY_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Litecoin) => LITECOIN_PUBKEY_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Litecoin) => LITECOIN_PUBKEY_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Stratis) => STRATIS_PUBKEY_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Stratis) => STRATIS_PUBKEY_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Ravencoin) => RAVENCOIN_PUBKEY_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Ravencoin) => RAVENCOIN_PUBKEY_ADDRESS_PREFIX_TEST,
                };
                Prefix::Pubkey(b)
            }
            Payload::ScriptHash(_) => {
                let b = match (network, chain) {
                    (Network::Bitcoin, Blockchain::Bitcoin) => BITCOIN_SCRIPT_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Bitcoin) => BITCOIN_SCRIPT_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Dogecoin) => DOGECOIN_SCRIPT_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Dogecoin) => DOGECOIN_SCRIPT_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Litecoin) => LITECOIN_SCRIPT_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Litecoin) => LITECOIN_SCRIPT_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Stratis) => STRATIS_SCRIPT_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Stratis) => STRATIS_SCRIPT_ADDRESS_PREFIX_TEST,
                    (Network::Bitcoin, Blockchain::Ravencoin) => RAVENCOIN_SCRIPT_ADDRESS_PREFIX_MAIN,
                    (_, Blockchain::Ravencoin) => RAVENCOIN_SCRIPT_ADDRESS_PREFIX_TEST,
                };
                Prefix::Script(b)
            }
            Payload::WitnessProgram { .. } => {
                let s = match (network, chain) {
                    (Network::Bitcoin, Blockchain::Bitcoin) => "bc".to_owned(),
                    (Network::Testnet, Blockchain::Bitcoin) => "tb".to_owned(),
                    (Network::Signet, Blockchain::Bitcoin) => "tb".to_owned(),
                    (Network::Regtest, Blockchain::Bitcoin) => "bcrt".to_owned(),
                    (Network::Bitcoin, Blockchain::Litecoin) => "ltc".to_owned(),
                    (Network::Testnet, Blockchain::Litecoin) => "tltc".to_owned(),
                    (Network::Bitcoin, Blockchain::Stratis) => "STRAX".to_owned(),
                    (Network::Testnet, Blockchain::Stratis) => "TSTRAX".to_owned(),
                    // FIXME: Ugh, this is hackish as hell.
                    (network, chain) =>
                        format!("segwit unsupported for network/chain {}/{}", network, chain),
                };
                Prefix::Segwit(s)
            }
        }
    }
}

/// A Bitcoin address.
///
/// ### Relevant BIPs
///
/// * [BIP13 - Address Format for pay-to-script-hash](https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki)
/// * [BIP16 - Pay to Script Hash](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
/// * [BIP141 - Segregated Witness (Consensus layer)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
/// * [BIP142 - Address Format for Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki)
/// * [BIP341 - Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
/// * [BIP350 - Bech32m format for v1+ witness addresses](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// The type of the address.
    pub payload: Payload,
    /// The network on which this address is usable.
    pub network: Network,
    /// Any prefix data we need to be able to serialize the address.
    pub prefix: Prefix,
}
serde_string_impl!(Address, "a Bitcoin address");

impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: &PublicKey, network: Network, chain: Blockchain) -> Address {
        let payload = Payload::p2pkh(pk);
        let prefix = Prefix::from_payload(&payload, network, chain);
        Address { network, payload, prefix }
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(
        script: &script::Script,
        network: Network,
        chain: Blockchain,
    ) -> Result<Address, Error> {
        let payload = Payload::p2sh(script)?;
        let prefix = Prefix::from_payload(&payload, network, chain);
        Ok(Address { network, payload, prefix })
    }

    /// Creates a witness pay to public key address from a public key.
    ///
    /// This is the native segwit address type for an output redeemable with a single signature.
    ///
    /// # Errors
    /// Will only return an error if an uncompressed public key is provided.
    pub fn p2wpkh(pk: &PublicKey, network: Network, chain: Blockchain) -> Result<Address, Error> {
        let payload = Payload::p2wpkh(pk)?;
        let prefix = Prefix::from_payload(&payload, network, chain);
        Ok(Address { network, payload, prefix })
    }

    /// Creates a pay to script address that embeds a witness pay to public key.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    ///
    /// # Errors
    /// Will only return an Error if an uncompressed public key is provided.
    pub fn p2shwpkh(pk: &PublicKey, network: Network, chain: Blockchain) -> Result<Address, Error> {
        let payload = Payload::p2shwpkh(pk)?;
        let prefix = Prefix::from_payload(&payload, network, chain);
        Ok(Address { network, payload, prefix })
    }

    /// Creates a witness pay to script hash address.
    pub fn p2wsh(script: &script::Script, network: Network, chain: Blockchain) -> Address {
        let payload = Payload::p2wsh(script);
        let prefix = Prefix::from_payload(&payload, network, chain);
        Address { network, payload, prefix }
    }

    /// Creates a pay to script address that embeds a witness pay to script hash address.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwsh(script: &script::Script, network: Network, chain: Blockchain) -> Address {
        let payload = Payload::p2shwsh(script);
        let prefix = Prefix::from_payload(&payload, network, chain);
        Address { network, payload, prefix }
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapBranchHash>,
        network: Network,
        chain: Blockchain,
    ) -> Address {
        let payload = Payload::p2tr(secp, internal_key, merkle_root);
        let prefix = Prefix::from_payload(&payload, network, chain);
        Address { network, payload, prefix }
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    ///
    /// This method is not recommended for use, [`Address::p2tr()`] should be used where possible.
    pub fn p2tr_tweaked(
        output_key: TweakedPublicKey,
        network: Network,
        chain: Blockchain,
    ) -> Address {
        let payload = Payload::p2tr_tweaked(output_key);
        let prefix = Prefix::from_payload(&payload, network, chain);
        Address { network, payload, prefix }
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    /// None if unknown, non-standard or related to the future witness version.
    pub fn address_type(&self) -> Option<AddressType> {
        match self.payload {
            Payload::PubkeyHash(_) => Some(AddressType::P2pkh),
            Payload::ScriptHash(_) => Some(AddressType::P2sh),
            Payload::WitnessProgram { version, program: ref prog } => {
                // BIP-141 p2wpkh or p2wsh addresses.
                match version {
                    WitnessVersion::V0 => match prog.len() {
                        20 => Some(AddressType::P2wpkh),
                        32 => Some(AddressType::P2wsh),
                        _ => None,
                    },
                    WitnessVersion::V1 if prog.len() == 32 => Some(AddressType::P2tr),
                    _ => None,
                }
            }
        }
    }

    /// Checks whether or not the address is following Bitcoin standardness rules.
    ///
    /// SegWit addresses with unassigned witness versions or non-standard program sizes are
    /// considered non-standard.
    pub fn is_standard(&self) -> bool { self.address_type().is_some() }

    /// Constructs an [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(
        script: &script::Script,
        network: Network,
        chain: Blockchain,
    ) -> Result<Address, Error> {
        let payload = Payload::from_script(script)?;
        let prefix = Prefix::from_payload(&payload, network, chain);
        Ok(Address { payload, network, prefix })
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> script::Script { self.payload.script_pubkey() }

    /// Creates a URI string *bitcoin:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, both the schema and the address become uppercase.
    /// If the address is base58, the schema is lowercase and the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    pub fn to_qr_uri(&self) -> String {
        let schema = match self.payload {
            Payload::WitnessProgram { .. } => "BITCOIN",
            _ => "bitcoin",
        };
        format!("{}:{:#}", schema, self)
    }

    /// Parsed addresses do not always have *one* network. The problem is that legacy testnet,
    /// regtest and signet addresse use the same prefix instead of multiple different ones. When
    /// parsing, such addresses are always assumed to be testnet addresses (the same is true for
    /// bech32 signet addresses). So if one wants to check if an address belongs to a certain
    /// network a simple comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use bitcoin::{Address, Network};
    ///
    /// let address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert!(address.is_valid_for_network(Network::Signet));
    ///
    /// assert_eq!(address.is_valid_for_network(Network::Bitcoin), false);
    ///
    /// let address: Address = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Bitcoin));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet), false);
    /// ```
    pub fn is_valid_for_network(&self, network: Network) -> bool {
        let is_legacy = match self.address_type() {
            Some(AddressType::P2pkh) | Some(AddressType::P2sh) => true,
            _ => false,
        };

        match (self.network, network) {
            (a, b) if a == b => true,
            (Network::Bitcoin, _) | (_, Network::Bitcoin) => false,
            (Network::Regtest, _) | (_, Network::Regtest) if !is_legacy => false,
            (Network::Testnet, _) | (Network::Regtest, _) | (Network::Signet, _) => true,
        }
    }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with either the
    /// hash of the given public key or the segwit redeem hash generated from the
    /// given key. For taproot addresses, the supplied key is assumed to be tweaked
    pub fn is_related_to_pubkey(&self, pubkey: &PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload.as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash == *payload)
            || (xonly_pubkey.serialize() == *payload)
            || (*segwit_redeem_hash(&pubkey_hash) == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    ///
    /// This will only work for Taproot addresses. The Public Key is
    /// assumed to have already been tweaked.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: &XOnlyPublicKey) -> bool {
        let payload = self.payload.as_bytes();
        payload == xonly_pubkey.serialize()
    }
}

// Put altcoin support in a separate impl block to make rebasing easier.
impl Address {
    fn pubkey_prefix(&self) -> u8 {
        match &self.prefix {
            Prefix::Pubkey(b) => *b,
            _ => match self.network {
                Network::Bitcoin => BITCOIN_PUBKEY_ADDRESS_PREFIX_MAIN,
                Network::Testnet | Network::Signet | Network::Regtest =>
                    BITCOIN_PUBKEY_ADDRESS_PREFIX_TEST,
            },
        }
    }

    fn script_prefix(&self) -> u8 {
        match &self.prefix {
            Prefix::Script(b) => *b,
            _ => match self.network {
                Network::Bitcoin => BITCOIN_SCRIPT_ADDRESS_PREFIX_MAIN,
                Network::Testnet | Network::Signet | Network::Regtest =>
                    BITCOIN_SCRIPT_ADDRESS_PREFIX_TEST,
            },
        }
    }

    fn segwit_prefix(&self) -> String {
        match &self.prefix {
            Prefix::Segwit(s) => s.to_string(),
            _ => match self.network {
                Network::Bitcoin => "bc",
                Network::Testnet | Network::Signet => "tb",
                Network::Regtest => "bcrt",
            }
            .to_string(),
        }
    }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let p2pkh_prefix = self.pubkey_prefix();
        let p2sh_prefix = self.script_prefix();
        let bech32_hrp = &self.segwit_prefix();
        let encoding =
            AddressEncoding { payload: &self.payload, p2pkh_prefix, p2sh_prefix, bech32_hrp };
        encoding.fmt(fmt)
    }
}

struct UpperWriter<W: fmt::Write>(W);

impl<W: fmt::Write> fmt::Write for UpperWriter<W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.0.write_char(c.to_ascii_uppercase())?;
        }
        Ok(())
    }
}

/// Extracts the bech32 prefix.
///
/// # Returns
/// The input slice if no prefix is found.
fn find_bech32_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Address, Error> {
        // try bech32
        let bech32_network = match find_bech32_prefix(s) {
            // note that upper or lowercase is allowed but NOT mixed case
            "bc" | "BC" | "ltc" | "LTC" | "X" => Some(Network::Bitcoin),
            "tb" | "TB" | "tltc" | "TLTC" | "q" => Some(Network::Testnet), // this may also be signet
            "bcrt" | "BCRT" => Some(Network::Regtest),
            _ => None,
        };
        if let Some(network) = bech32_network {
            // decode as bech32
            let (hrp, payload, variant) = bech32::decode(s)?;
            let prefix = Prefix::segwit(&hrp);
            if payload.is_empty() {
                return Err(Error::EmptyBech32Payload);
            }

            // Get the script version and program (converted from 5-bit to 8-bit)
            let (version, program): (WitnessVersion, Vec<u8>) = {
                let (v, p5) = payload.split_at(1);
                (WitnessVersion::try_from(v[0])?, bech32::FromBase32::from_base32(p5)?)
            };

            if program.len() < 2 || program.len() > 40 {
                return Err(Error::InvalidWitnessProgramLength(program.len()));
            }

            // Specific segwit v0 check.
            if version == WitnessVersion::V0 && (program.len() != 20 && program.len() != 32) {
                return Err(Error::InvalidSegwitV0ProgramLength(program.len()));
            }

            // Encoding check
            let expected = version.bech32_variant();
            if expected != variant {
                return Err(Error::InvalidBech32Variant { expected, found: variant });
            }

            return Ok(Address {
                payload: Payload::WitnessProgram { version, program },
                network,
                prefix,
            });
        }

        // Base58
        if s.len() > 50 {
            return Err(Error::Base58(base58::Error::InvalidLength(s.len() * 11 / 15)));
        }
        let data = base58::from_check(s)?;
        if data.len() != 21 {
            return Err(Error::Base58(base58::Error::InvalidLength(data.len())));
        }

        // At this stage we do not know what chain we are on, so we cannot use `Prefix::from_payload()`.
        let prefix_byte = data[0];

        #[allow(unreachable_patterns)] // Duplicate byte values left in to assist clarity.
        // BTC | DOGE | LTC | STRAX | RVN
        let (network, payload, prefix) = match prefix_byte {
            BITCOIN_PUBKEY_ADDRESS_PREFIX_MAIN
            | DOGECOIN_PUBKEY_ADDRESS_PREFIX_MAIN
            | LITECOIN_PUBKEY_ADDRESS_PREFIX_MAIN
            | STRATIS_PUBKEY_ADDRESS_PREFIX_MAIN
            | RAVENCOIN_PUBKEY_ADDRESS_PREFIX_MAIN => (
                Network::Bitcoin,
                Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()),
                Prefix::pubkey(prefix_byte),
            ),
            BITCOIN_SCRIPT_ADDRESS_PREFIX_MAIN
            | DOGECOIN_SCRIPT_ADDRESS_PREFIX_MAIN
            | LITECOIN_SCRIPT_ADDRESS_PREFIX_MAIN
            | STRATIS_SCRIPT_ADDRESS_PREFIX_MAIN
            | RAVENCOIN_SCRIPT_ADDRESS_PREFIX_MAIN => (
                Network::Bitcoin,
                Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()),
                Prefix::script(prefix_byte),
            ),
            BITCOIN_PUBKEY_ADDRESS_PREFIX_TEST
            | DOGECOIN_PUBKEY_ADDRESS_PREFIX_TEST
            | LITECOIN_PUBKEY_ADDRESS_PREFIX_TEST
            | STRATIS_PUBKEY_ADDRESS_PREFIX_TEST
            | RAVENCOIN_PUBKEY_ADDRESS_PREFIX_TEST => (
                Network::Testnet,
                Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()),
                Prefix::pubkey(prefix_byte),
            ),
            BITCOIN_SCRIPT_ADDRESS_PREFIX_TEST
            | DOGECOIN_SCRIPT_ADDRESS_PREFIX_TEST
            | LITECOIN_SCRIPT_ADDRESS_PREFIX_TEST
            | STRATIS_SCRIPT_ADDRESS_PREFIX_TEST
            | RAVENCOIN_SCRIPT_ADDRESS_PREFIX_TEST => (
                Network::Testnet,
                Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()),
                Prefix::script(prefix_byte),
            ),
            x => return Err(Error::Base58(base58::Error::InvalidAddressVersion(x))),
        };

        Ok(Address { network, payload, prefix })
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

/// Convert a byte array of a pubkey hash into a segwit redeem hash
fn segwit_redeem_hash(pubkey_hash: &[u8]) -> crate::hashes::hash160::Hash {
    let mut sha_engine = sha256::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash);
    crate::hashes::hash160::Hash::from_engine(sha_engine)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use secp256k1::XOnlyPublicKey;

    use super::*;
    use crate::blockdata::script::Script;
    use crate::hashes::hex::{FromHex, ToHex};
    use crate::network::constants::Network::{Bitcoin, Testnet};
    use crate::util::key::PublicKey;

    macro_rules! hex (($hex:literal) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_key (($hex:literal) => (PublicKey::from_slice(&hex!($hex)).unwrap()));
    macro_rules! hex_script (($hex:literal) => (Script::from(hex!($hex))));
    macro_rules! hex_pubkeyhash (($hex:literal) => (PubkeyHash::from_hex(&$hex).unwrap()));
    macro_rules! hex_scripthash (($hex:literal) => (ScriptHash::from_hex($hex).unwrap()));

    const CHAIN: Blockchain = Blockchain::Bitcoin;

    fn roundtrips(addr: &Address) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), addr.network, CHAIN).as_ref(),
            Ok(addr),
            "script round-trip failed for {}",
            addr,
        );
        //TODO: add serde roundtrip after no-strason PR
    }

    #[test]
    fn test_p2pkh_address_58() {
        let network = Bitcoin;
        let payload =
            Payload::PubkeyHash(hex_pubkeyhash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070"));
        let prefix = Prefix::from_payload(&payload, network, CHAIN);

        let addr = Address { network, payload, prefix };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );
        assert_eq!(&addr.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = hex_key!("048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183");
        let addr = Address::p2pkh(&key, Bitcoin, CHAIN);
        assert_eq!(&addr.to_string(), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");

        let key = hex_key!("03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f");
        let addr = Address::p2pkh(&key, Testnet, CHAIN);
        assert_eq!(&addr.to_string(), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_address_58() {
        let network = Bitcoin;
        let payload =
            Payload::ScriptHash(hex_scripthash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070"));
        let prefix = Prefix::from_payload(&payload, network, CHAIN);

        let addr = Address { network, payload, prefix };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );
        assert_eq!(&addr.to_string(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = hex_script!("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae");
        let addr = Address::p2sh(&script, Testnet, CHAIN).unwrap();
        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse_for_large_script() {
        let script = hex_script!("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123");
        assert_eq!(Address::p2sh(&script, Testnet, CHAIN), Err(Error::ExcessiveScriptSize));
    }

    #[test]
    fn test_p2wpkh() {
        // stolen from Bitcoin transaction: b3c8c2b6cfc335abbcb2c7823a8453f55d64b2b5125a9a61e8737230cdb8ce20
        let mut key =
            hex_key!("033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc");
        let addr = Address::p2wpkh(&key, Bitcoin, CHAIN).unwrap();
        assert_eq!(&addr.to_string(), "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw");
        assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
        roundtrips(&addr);

        // Test uncompressed pubkey
        key.compressed = false;
        assert_eq!(Address::p2wpkh(&key, Bitcoin, CHAIN), Err(Error::UncompressedPubkey));
    }

    #[test]
    fn test_p2wsh() {
        // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
        let script = hex_script!("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae");
        let addr = Address::p2wsh(&script, Bitcoin, CHAIN);
        assert_eq!(
            &addr.to_string(),
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2shwpkh() {
        // stolen from Bitcoin transaction: ad3fd9c6b52e752ba21425435ff3dd361d6ac271531fc1d2144843a9f550ad01
        let mut key =
            hex_key!("026c468be64d22761c30cd2f12cbc7de255d592d7904b1bab07236897cc4c2e766");
        let addr = Address::p2shwpkh(&key, Bitcoin, CHAIN).unwrap();
        assert_eq!(&addr.to_string(), "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);

        // Test uncompressed pubkey
        key.compressed = false;
        assert_eq!(Address::p2wpkh(&key, Bitcoin, CHAIN), Err(Error::UncompressedPubkey));
    }

    #[test]
    fn test_p2shwsh() {
        // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
        let script = hex_script!("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae");
        let addr = Address::p2shwsh(&script, Bitcoin, CHAIN);
        assert_eq!(&addr.to_string(), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_non_existent_segwit_version() {
        // 40-byte program
        let program = hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        );
        let network = Network::Bitcoin;
        let payload = Payload::WitnessProgram { version: WitnessVersion::V13, program };
        let prefix = Prefix::from_payload(&payload, network, CHAIN);

        let addr = Address { payload, network, prefix };
        roundtrips(&addr);
    }

    #[test]
    fn test_address_type() {
        let addresses = [
            ("1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY", Some(AddressType::P2pkh)),
            ("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k", Some(AddressType::P2sh)),
            ("bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw", Some(AddressType::P2wpkh)),
            (
                "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
                Some(AddressType::P2wsh),
            ),
            (
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                Some(AddressType::P2tr),
            ),
            // Related to future extensions, addresses are valid but have no type
            // segwit v1 and len != 32
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", None),
            // segwit v2
            ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", None),
        ];
        for (address, expected_type) in &addresses {
            let addr = Address::from_str(address).unwrap();
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    fn test_bip173_350_vectors() {
        // Test vectors valid under both BIP-173 and BIP-350
        let valid_vectors = [
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("BC1SW50QGDZ25J", "6002751e"),
            ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
            ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        ];
        for vector in &valid_vectors {
            let addr: Address = vector.0.parse().unwrap();
            assert_eq!(&addr.script_pubkey().as_bytes().to_hex(), vector.1);
            roundtrips(&addr);
        }

        let invalid_vectors = [
            // 1. BIP-350 test vectors
            // Invalid human-readable part
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            // Invalid checksums (Bech32 instead of Bech32m):
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            // Invalid character in checksum
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            // Invalid witness version
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            // Invalid program length (1 byte)
            "bc1pw5dgrnzv",
            // Invalid program length (41 bytes)
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            // Invalid program length for witness version 0 (per BIP141)
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            // Mixed case
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            // zero padding of more than 4 bits
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            // Non-zero padding in 8-to-5 conversion
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            // Empty data section
            "bc1gmk9yu",
            // 2. BIP-173 test vectors
            // Invalid human-readable part
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            // Invalid checksum
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            // Invalid witness version
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            // Invalid program length
            "bc1rw5uspcuh",
            // Invalid program length
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            // Invalid program length for witness version 0 (per BIP141)
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            // Mixed case
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            // zero padding of more than 4 bits
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            // Non-zero padding in 8-to-5 conversion
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            // Final test for empty data section is the same as above in BIP-350

            // 3. BIP-173 valid test vectors obsolete by BIP-350
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            "BC1SW50QA3JX3S",
            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        ];
        for vector in &invalid_vectors {
            assert!(vector.parse::<Address>().is_err());
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        let addr = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );

        let addr = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );

        let addr =
            Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
        );

        let addr = Address::from_str("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("001454d26dddb59c7073c6a197946ea1841951fa7a74")
        );
    }

    #[test]
    fn test_qr_string() {
        for el in
            ["132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM", "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k"].iter()
        {
            let addr = Address::from_str(el).unwrap();
            assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el));
        }

        for el in [
            "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl",
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
        ]
        .iter()
        {
            let addr = Address::from_str(el).unwrap();
            assert_eq!(addr.to_qr_uri(), format!("BITCOIN:{}", el.to_ascii_uppercase()));
        }
    }

    #[test]
    fn test_valid_networks() {
        let legacy_payload = &[
            Payload::PubkeyHash(PubkeyHash::all_zeros()),
            Payload::ScriptHash(ScriptHash::all_zeros()),
        ];
        let segwit_payload = (0..=16)
            .map(|version| Payload::WitnessProgram {
                version: WitnessVersion::try_from(version).unwrap(),
                program: vec![],
            })
            .collect::<Vec<_>>();

        const LEGACY_EQUIVALENCE_CLASSES: &[&[Network]] =
            &[&[Network::Bitcoin], &[Network::Testnet, Network::Regtest, Network::Signet]];
        const SEGWIT_EQUIVALENCE_CLASSES: &[&[Network]] =
            &[&[Network::Bitcoin], &[Network::Regtest], &[Network::Testnet, Network::Signet]];

        fn test_addr_type(payloads: &[Payload], equivalence_classes: &[&[Network]]) {
            for pl in payloads {
                for addr_net in equivalence_classes.iter().flat_map(|ec| ec.iter()) {
                    for valid_net in equivalence_classes
                        .iter()
                        .filter(|ec| ec.contains(addr_net))
                        .flat_map(|ec| ec.iter())
                    {
                        let network = *addr_net;
                        let payload = pl.clone();
                        let prefix = Prefix::from_payload(&payload, network, CHAIN);

                        let addr = Address { network, payload, prefix };
                        assert!(addr.is_valid_for_network(*valid_net));
                    }

                    for invalid_net in equivalence_classes
                        .iter()
                        .filter(|ec| !ec.contains(addr_net))
                        .flat_map(|ec| ec.iter())
                    {
                        let network = *addr_net;
                        let payload = pl.clone();
                        let prefix = Prefix::from_payload(&payload, network, CHAIN);

                        let addr = Address { network, payload, prefix };
                        assert!(!addr.is_valid_for_network(*invalid_net));
                    }
                }
            }
        }

        test_addr_type(legacy_payload, LEGACY_EQUIVALENCE_CLASSES);
        test_addr_type(&segwit_payload, SEGWIT_EQUIVALENCE_CLASSES);
    }

    #[test]
    fn p2tr_from_untweaked() {
        //Test case from BIP-086
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let secp = Secp256k1::verification_only();
        let address = Address::p2tr(&secp, internal_key, None, Network::Bitcoin, CHAIN);
        assert_eq!(
            address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(address.address_type(), Some(AddressType::P2tr));
        roundtrips(&address);
    }

    #[test]
    fn test_is_related_to_pubkey_p2wpkh() {
        let address_string = "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4";
        let address = Address::from_str(address_string).expect("address");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2shwpkh() {
        let address_string = "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs";
        let address = Address::from_str(address_string).expect("address");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh() {
        let address_string = "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx";
        let address = Address::from_str(address_string).expect("address");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);

        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p";
        let address = Address::from_str(address_string).expect("address");

        let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2tr() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin, CHAIN);

        assert_eq!(
            address,
            Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
                .expect("address")
        );

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey));
    }

    #[test]
    fn test_is_related_to_xonly_pubkey() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin, CHAIN);

        assert_eq!(
            address,
            Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
                .expect("address")
        );

        let result = address.is_related_to_xonly_pubkey(&xonly_pubkey);
        assert!(result);
    }

    #[test]
    fn test_fail_address_from_script() {
        let bad_p2wpkh = hex_script!("0014dbc5b0a8f9d4353b4b54c3db48846bb15abfec");
        let bad_p2wsh =
            hex_script!("00202d4fa2eb233d008cc83206fa2f4f2e60199000f5b857a835e3172323385623");
        let invalid_segwitv0_script = hex_script!("001161458e330389cd0437ee9fe3641d70cc18");
        let expected = Err(Error::UnrecognizedScript);

        assert_eq!(Address::from_script(&bad_p2wpkh, Network::Bitcoin, CHAIN), expected);
        assert_eq!(Address::from_script(&bad_p2wsh, Network::Bitcoin, CHAIN), expected);
        assert_eq!(
            Address::from_script(&invalid_segwitv0_script, Network::Bitcoin, CHAIN),
            Err(Error::InvalidSegwitV0ProgramLength(17))
        );
    }

    #[test]
    fn valid_address_parses_correctly() {
        let addr = AddressType::from_str("p2tr").expect("false negative while parsing address");
        assert_eq!(addr, AddressType::P2tr);
    }

    #[test]
    fn invalid_address_parses_error() {
        let got = AddressType::from_str("invalid");
        let want = Err(Error::UnknownAddressType("invalid".to_string()));
        assert_eq!(got, want);
    }

    #[test]
    fn parse_bitcoin_address_from_str() {
        // ref: https://en.bitcoin.it/wiki/List_of_address_prefixes
        let addrs = vec![
            // Mainnet addresses.
            "17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem", // Pubkey hash (P2PKH address)
            "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX", // Script hash (P2SH address)
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // Bech32 pubkey hash or script hash
            // Testnet addresses.
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", // Pubkey hash (P2PKH address)
            "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc", // Script hash (P2SH address)
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // Bech32 pubkey hash or script hash

                                                  // These addresses don't parse, should they?

                                                  // "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ", // Private key (WIF, compressed pubkey)
                                                  // "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5e4cp9LB", // BIP32 pubkey
                                                  // "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx", // BIP32 private key
                                                  // "92Pg46rUhgTT7romnV7iGW6W1gbGdeezqdbJCzShkCsYNzyyNcc", // Testnet Private key (WIF, uncompressed pubkey)
                                                  // "cNJFgo1driFnPcBdBX8BrJrpxchBWXwXCvNH5SoSkdcF6JXXwHMm", // Testnet Private key (WIF, compressed pubkey)
                                                  // "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLNGbhd2pq7ZtDiPYTfJ7iBenLVQpYgSQqPjUsQeJXH8VQ8xA67D", // Testnet BIP32 pubkey
                                                  // "tprv8ZgxMBicQKsPcsbCVeqqF1KVdH7gwDJbxbzpCxDUsoXHdb6SnTPYxdwSAKDC6KKJzv7khnNWRAJQsRA8BBQyiSfYnRt6zuu4vZQGKjeW4YF", // Testnet BIP32 private key
        ];

        for s in addrs.iter() {
            let _ = Address::from_str(s).expect(&format!("Failed to parse address string: {}", s));
        }
    }

    // TODO: Add full list of acceptable Dogecoin address formats like bitcoin above.
    #[test]
    fn parse_dogecoin_address_from_str() {
        let addrs = vec![
            // Mainnet addresses.
            "DMqRVLrhbam3Kcfddpxd6EYvEBbpi3bEpP", // Pubkey hash (P2PKH address)
            "9yepMVtXajUmFhBrN1zqR73dwFu2rkNwwz", // Pubkey hash (P2PKH address)
            "A5gpS8g8Jm9apnxhjMxfJgdFCkXvRuruAZ", // Pubkey hash (P2PKH address)
            // Testnet addresses.
            "nmX62VXvTCVA5wLd85avsuC7ejC4obznYb", // Pubkey hash (P2PKH address)
                                                  // Script hash test is the same as Bitcoin
        ];
        for s in addrs.iter() {
            let _ = Address::from_str(s).expect(&format!("Failed to parse address string: {}", s));
        }
    }

    #[test]
    fn parse_litecoin_address_from_str() {
        let addrs = vec![
            // Mainnet addresses.
            "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1", // Pubkey hash (P2PKH address)
            "3MSvaVbVFFLML86rt5eqgA9SvW23upaXdY", // Script hash (P2SH address) - Legacy/Deprecated
            "MTf4tP1TCNBn8dNkyxeBVoPrFCcVzxJvvh", // Pubkey hash (P2PKH address) // Script hash (P2SH address)
            "ltc1qd03r6knplnv3c9qe22vkwchh2yd3e0lkvakjac", // Bech32 pubkey hash or script hash
            // Testnet addresses.
            // Pubkey hash test is the same as Bitcoin.
            "2N2PJEucf6QY2kNFuJ4chQEBoyZWszRQE16", // Script hash (P2SH address) - Legacy/Deprecated
            "QVk4MvUu7Wb7tZ1wvAeiUvdF7wxhvpyLLK",  // Script hash (P2SH address)
            "tltc1qcefwt8q647lstt5829exynqnecr9uxq9pk3yr5", // Bech32 pubkey hash or script hash
        ];
        for s in addrs.iter() {
            let _ = Address::from_str(s).expect(&format!("Failed to parse address string: {}", s));
        }
    }

    #[test]
    fn parse_ravencoin_address_from_str() {
        let addrs = vec![
            // Mainnet addresses.
            "RVG96MbaKEDFzzj9NzbAuxkDt86KAm2Qj5", // Pubkey hash (P2PKH address)
            "rFSRmpYa48SY835vija8JMAfXnAteJr9nx", // Script hash (P2SH address)
            // Testnet addresses.
            "mrRncXkHjrhtoipKauJF3mKgZjUbtXC6b3", // Pubkey hash (P2PKH address)
            "n3d1tRxEUEpx7cUHex38D6R5pz6srH1akt", // Script hash (P2SH address)
        ];
        for s in addrs.iter() {
            let _ = Address::from_str(s).expect(&format!("Failed to parse address string: {}", s));
        }
    }
}
