use rmpv;
use std::fmt;
use std::ops::Deref;
use std::str::{self, FromStr};
use trust_dns::rr::Label;
#[cfg(feature = "pepbutd")]
use trust_dns::rr;

use zone::{Msgpack, MsgpackError};

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
    fn from_msgpack(value: &rmpv::Value, labels: &[Label]) -> Result<Self, MsgpackError> {
        let name_labels = value
            .as_array()
            .ok_or(MsgpackError::NotArray)?
            .iter()
            .map(|n| n.as_u64().ok_or(MsgpackError::NotUint).map(|x| x as usize))
            .collect::<Result<Vec<usize>, _>>()?;

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

    fn to_msgpack(&self, labels: &mut Vec<Label>) -> rmpv::Value {
        let mut labels: Vec<rmpv::Value> = self.labels
            .iter()
            .map(|l| match labels.iter().position(|x| x == l.deref()) {
                Some(n) => (n + 1).into(),
                None => {
                    labels.push(l.clone());
                    labels.len().into()
                }
            })
            .collect();
        if self.is_fqdn {
            labels.push(0.into());
        }
        rmpv::Value::Array(labels)
    }
}

#[cfg(feature = "pepbutd")]
#[derive(Debug, Fail)]
pub enum TrustDnsConversionError {
    #[fail(display = "trust-dns-proto name creation error")]
    NameCreation,
    #[fail(display = "name is not FQDN and origin was not provided")]
    NoOrigin,
}

#[cfg(feature = "pepbutd")]
impl Name {
    pub fn to_name(&self, origin: Option<&Name>) -> Result<rr::Name, TrustDnsConversionError> {
        let labels = self.labels
            .iter()
            .chain(match (self.is_fqdn, origin) {
                (true, _) => [].iter(),
                (false, Some(n)) => n.labels.iter(),
                (false, None) => return Err(TrustDnsConversionError::NoOrigin),
            })
            .map(|x| x.deref().to_owned());
        Ok(rr::Name::from_labels(labels).map_err(|_| TrustDnsConversionError::NameCreation)?)
    }

    pub fn to_lower_name(
        &self,
        origin: Option<&Name>,
    ) -> Result<rr::LowerName, TrustDnsConversionError> {
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
            ($e:expr) => {
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
