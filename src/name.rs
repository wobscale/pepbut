use failure;
use rmp;
use std::fmt;
use std::io::{Read, Write};
use std::str::{self, FromStr};
use trust_dns::rr::Label;
#[cfg(feature = "pepbutd")]
use trust_dns::rr;

use zone::Msgpack;

#[derive(Debug, Fail)]
pub enum ParseNameError {
    #[fail(display = "label contains invalid characters")]
    InvalidLabel,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Name {
    labels: Vec<Label>,
    is_fqdn: bool,
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

        let (s, is_fqdn) = if s.ends_with('.') {
            (&s[0..(s.len() - 1)], true)
        } else {
            (s, false)
        };

        Ok(Name {
            labels: s.split('.')
                .map(|l| Label::from_utf8(l).map_err(|_| ParseNameError::InvalidLabel))
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
                match labels.iter().position(|x| x == label) {
                    Some(n) => n + 1,
                    None => {
                        labels.push(label.clone());
                        labels.len()
                    }
                } as u64,
            )?;
        }

        if self.is_fqdn {
            rmp::encode::write_uint(writer, 0)?;
        }

        Ok(())
    }
}

#[cfg(feature = "pepbutd")]
impl Name {
    pub fn to_name(&self, origin: Option<&Name>) -> Result<rr::Name, failure::Error> {
        rr::Name::from_labels(self.labels.iter().chain(match (self.is_fqdn, origin) {
            (true, _) => [].iter(),
            (false, Some(n)) => n.labels.iter(),
            (false, None) => bail!("no origin given on non-FQDN name"),
        })).map_err(|e| format_err!("{:?}", e))
    }

    pub fn to_lower_name(&self, origin: Option<&Name>) -> Result<rr::LowerName, failure::Error> {
        self.to_name(origin).map(|x| x.into())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use trust_dns::rr::Label;

    use name::Name;

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
