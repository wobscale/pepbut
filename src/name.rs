//! Domain names and labels.

// ParseNameError uses a Debug format for uts46::Errors which is an opaque type. Because Fail is
// derived, we can't apply this cfg_attr to only that struct.
#![cfg_attr(feature = "cargo-clippy", allow(use_debug))]

use failure;
use idna::uts46;
use rmp;
use std::fmt;
use std::io::{Read, Write};
use std::sync::Arc;
use std::str::{self, FromStr};

use Msgpack;

/// Errors that can occur while parsing a `Name`.
#[derive(Debug, Fail)]
pub enum ParseNameError {
    /// The label contains invalid characters according to UTS #46.
    #[fail(display = "label contains invalid characters: {:?}", _0)]
    InvalidLabel(uts46::Errors),
    /// The label is longer than 63 characters.
    #[fail(display = "label exceeds maximum length of 63: {}", _0)]
    LabelTooLong(usize),
}

/// A label is a single element in a domain name. For the domain name `example.invalid`, there are
/// two labels, `example` and `invalid`.
///
/// Labels in pepbut are atomically reference-counted byte arrays (`Arc<[u8]>`). The byte arrays
/// always represent the canonical representation of a label (the result of [UTS #46][uts46]
/// processing, commonly the lowercase ASCII/Punycode form).
///
/// [uts46]: https://www.unicode.org/reports/tr46/
///
/// Making the byte arrays reference-counted is part of making the pepbut name server more memory
/// efficient. The other part is [`Zone`](../zone/struct.Zone.html)'s packing of labels by
/// reference, allowing each label to be stored in memory exactly once per zone when read from a
/// zone file.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Label(Arc<[u8]>);

// `is_empty` makes little sense with a data type that is required to be non-empty
#[cfg_attr(feature = "cargo-clippy", allow(len_without_is_empty))]
impl Label {
    /// Validates and constructs a label from a string. This method normalizes the label to
    /// lowercase ASCII, converting non-ASCII characters into Punycode according to UTS #46.
    pub fn from_utf8(s: &str) -> Result<Label, ParseNameError> {
        if s.starts_with('_') && s.is_ascii()
            && s.chars().skip(1).all(|c| c.is_alphanumeric() || c == '-')
        {
            Label::from_raw_bytes(s.to_lowercase().as_bytes())
        } else {
            Label::from_raw_bytes(
                uts46::to_ascii(
                    s,
                    uts46::Flags {
                        use_std3_ascii_rules: true,
                        transitional_processing: true,
                        verify_dns_length: true,
                    },
                ).map_err(ParseNameError::InvalidLabel)?
                    .as_bytes(),
            )
        }
    }

    /// Constructs a label from a raw byte array. This method only checks that the length of the
    /// label is 63 characters or less, and assumes that the bytes are lowercase ASCII. Because of
    /// these assumptions the method is private, and only used from `from_utf8` and
    /// `Msgpack::from_msgpack`.
    fn from_raw_bytes(bytes: &[u8]) -> Result<Label, ParseNameError> {
        if bytes.len() > 63 {
            Err(ParseNameError::LabelTooLong(bytes.len()))
        } else {
            Ok(Label(Arc::from(bytes)))
        }
    }

    /// Returns the length of the byte array of this label.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            uts46::to_unicode(
                str::from_utf8(&self.0).expect("label can only contain UTF-8 bytes"),
                uts46::Flags {
                    use_std3_ascii_rules: true,
                    transitional_processing: true,
                    verify_dns_length: true,
                }
            ).0
        )
    }
}

impl Msgpack for Label {
    fn from_msgpack<R>(reader: &mut R, _: &[Label]) -> Result<Self, failure::Error>
    where
        R: Read,
    {
        let len = rmp::decode::read_str_len(reader)? as usize;
        let mut buf = Vec::with_capacity(len);
        buf.resize(len, 0);
        reader.read_exact(&mut buf[..])?;

        Ok(Label::from_raw_bytes(&buf[..])?)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
    fn to_msgpack<W>(&self, writer: &mut W, _: &mut Vec<Label>) -> Result<(), failure::Error>
    where
        W: Write,
    {
        rmp::encode::write_str_len(writer, self.len() as u32)?;
        writer.write_all(&self.0)?;

        Ok(())
    }
}

/// A domain name, which may or may not be a fully-qualified domain name.
#[derive(Clone, Debug, PartialEq)]
pub struct Name {
    /// The labels that make up this name.
    labels: Vec<Label>,
    /// Whether this name represents a fully-qualified domain name (FQDN).
    is_fqdn: bool,
}

impl Name {
    /// Convert this object to a `FQDN`, given an origin the name belongs to.
    pub fn to_full_name(&self, origin: Option<&FQDN>) -> Result<FQDN, failure::Error> {
        Ok(if self.is_fqdn {
            FQDN {
                labels: self.labels.clone(),
            }
        } else if let Some(origin) = origin {
            FQDN {
                labels: self.labels
                    .clone()
                    .into_iter()
                    .chain(origin.labels.clone().into_iter())
                    .collect(),
            }
        } else {
            bail!("tried to make full name from non-FQDN without an origin");
        })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", label)?;
        }
        if self.is_fqdn {
            write!(f, ".")?;
        }
        Ok(())
    }
}

impl FromStr for Name {
    type Err = ParseNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Name {
                labels: Vec::new(),
                is_fqdn: false,
            });
        }

        let (name, is_fqdn) = if s.ends_with('.') {
            (&s[0..(s.len() - 1)], true)
        } else {
            (s, false)
        };

        Ok(Name {
            labels: name.split('.')
                .map(Label::from_utf8)
                .collect::<Result<Vec<_>, _>>()?,
            is_fqdn,
        })
    }
}

impl Msgpack for Name {
    fn from_msgpack<R>(reader: &mut R, labels: &[Label]) -> Result<Self, failure::Error>
    where
        R: Read,
    {
        let label_len = rmp::decode::read_array_len(reader)? as usize;
        let mut name_labels = Vec::with_capacity(label_len);
        for _ in 0..label_len {
            name_labels.push(rmp::decode::read_int(reader)?);
        }

        let (name_labels, is_fqdn) = if name_labels.ends_with(&[0]) {
            (&name_labels[0..(name_labels.len() - 1)], true)
        } else {
            (&name_labels[..], false)
        };

        Ok(Name {
            labels: name_labels.iter().map(|l| labels[*l - 1].clone()).collect(),
            is_fqdn,
        })
    }

    #[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
    fn to_msgpack<W>(&self, writer: &mut W, labels: &mut Vec<Label>) -> Result<(), failure::Error>
    where
        W: Write,
    {
        rmp::encode::write_array_len(
            writer,
            if self.is_fqdn {
                self.labels.len() + 1
            } else {
                self.labels.len()
            } as u32,
        )?;

        for label in &self.labels {
            rmp::encode::write_uint(
                writer,
                if let Some(n) = labels.iter().position(|x| x == label) {
                    n + 1
                } else {
                    labels.push(label.clone());
                    labels.len()
                } as u64,
            )?;
        }

        if self.is_fqdn {
            rmp::encode::write_uint(writer, 0)?;
        }

        Ok(())
    }
}

/// A fully-qualified domain name. This object differs from `Name` in that it *must* always be
/// fully-qualified.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FQDN {
    /// The labels that make up this name.
    labels: Vec<Label>,
}

impl FQDN {
    /// Convert this object to a `Name`.
    pub fn to_name(&self) -> Name {
        Name {
            labels: self.labels.clone(),
            is_fqdn: true,
        }
    }
}

impl fmt::Display for FQDN {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for label in &self.labels {
            write!(f, "{}.", label)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use name::{Label, Name};

    #[test]
    fn display() {
        for s in &["buttslol.net.", "subdomain", "☃.net.", ""] {
            assert_eq!(format!("{}", Name::from_str(s).unwrap()), s.to_owned());
        }
    }

    #[test]
    fn from_str() {
        macro_rules! label {
            ($e: expr) => {
                Label::from_utf8($e).unwrap()
            };
        }

        assert_eq!(
            Name::from_str("buttslol.net.").unwrap(),
            Name {
                labels: vec![label!("buttslol"), label!("net")],
                is_fqdn: true,
            }
        );
        assert_eq!(
            Name::from_str("subdomain").unwrap(),
            Name {
                labels: vec![label!("subdomain")],
                is_fqdn: false,
            }
        );
        assert_eq!(
            Name::from_str("☃.net.").unwrap(),
            Name {
                labels: vec![label!("☃"), label!("net")],
                is_fqdn: true,
            }
        );
        assert_eq!(
            Name::from_str("").unwrap(),
            Name {
                labels: vec![],
                is_fqdn: false,
            }
        );
    }
}
