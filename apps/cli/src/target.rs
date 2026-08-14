//! Parsing of the PRD 9.2 connect-target grammar from CLI words.

use protonwire_client::ClientError;
use protonwire_frontend_api::{ConnectTarget, RpcError, RpcErrorCode, SpecialClass};

/// Parses target words like `["fastest"]`, `["country", "GB"]`,
/// `["server", "UK#42"]`, `["group", "proton:fastest-country"]`.
pub struct ConnectTargetArgs;

impl ConnectTargetArgs {
    /// Parses the word list into a typed [`ConnectTarget`].
    pub fn parse(words: &[String]) -> Result<ConnectTarget, ClientError> {
        let invalid = |detail: String| {
            ClientError::Rpc(RpcError::new(
                RpcErrorCode::InvalidParams,
                format!("invalid connect target: {detail} (see `protonwire connect --help`)"),
            ))
        };
        let [head, rest @ ..] = words else {
            return Err(invalid(
                "expected a target such as `fastest` or `country GB`".into(),
            ));
        };
        match head.as_str() {
            "fastest" if rest.is_empty() => Ok(ConnectTarget::Fastest),
            "random" if rest.is_empty() => Ok(ConnectTarget::Random),
            "p2p" if rest.is_empty() => Ok(ConnectTarget::Special {
                class: SpecialClass::P2p,
            }),
            "tor" if rest.is_empty() => Ok(ConnectTarget::Special {
                class: SpecialClass::Tor,
            }),
            "secure-core" => Ok(ConnectTarget::SecureCore {
                entry_country: None,
                exit_country: None,
            }),
            "country" | "state" | "city" | "server" | "gateway" | "group" | "profile" => {
                let [value] = rest else {
                    return Err(invalid(format!("`{head}` expects exactly one value")));
                };
                Ok(match head.as_str() {
                    "country" => ConnectTarget::Country {
                        country: value.clone(),
                    },
                    "state" => ConnectTarget::State {
                        state_or_region: value.clone(),
                    },
                    "city" => ConnectTarget::City {
                        city: value.clone(),
                    },
                    "server" => ConnectTarget::Server {
                        server: value.clone(),
                    },
                    "gateway" => ConnectTarget::Gateway {
                        gateway: value.clone(),
                    },
                    "group" => ConnectTarget::Group {
                        group_id: value.clone(),
                    },
                    "profile" => ConnectTarget::Profile {
                        profile: value.clone(),
                    },
                    _ => unreachable!("head matched above"),
                })
            }
            other => Err(invalid(format!("unknown target `{other}`"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bare_targets_parse() {
        assert_eq!(
            ConnectTargetArgs::parse(&words(&["fastest"])).unwrap(),
            ConnectTarget::Fastest
        );
        assert_eq!(
            ConnectTargetArgs::parse(&words(&["random"])).unwrap(),
            ConnectTarget::Random
        );
        assert_eq!(
            ConnectTargetArgs::parse(&words(&["p2p"])).unwrap(),
            ConnectTarget::Special {
                class: SpecialClass::P2p
            }
        );
        assert_eq!(
            ConnectTargetArgs::parse(&words(&["secure-core"])).unwrap(),
            ConnectTarget::SecureCore {
                entry_country: None,
                exit_country: None
            }
        );
    }

    #[test]
    fn valued_targets_parse() {
        assert_eq!(
            ConnectTargetArgs::parse(&words(&["country", "GB"])).unwrap(),
            ConnectTarget::Country {
                country: "GB".into()
            }
        );
        assert_eq!(
            ConnectTargetArgs::parse(&words(&["server", "UK#42"])).unwrap(),
            ConnectTarget::Server {
                server: "UK#42".into()
            }
        );
        assert_eq!(
            ConnectTargetArgs::parse(&words(&["group", "proton:fastest-country"])).unwrap(),
            ConnectTarget::Group {
                group_id: "proton:fastest-country".into()
            }
        );
    }

    #[test]
    fn grammar_violations_are_invalid_params() {
        assert!(ConnectTargetArgs::parse(&words(&[])).is_err());
        assert!(ConnectTargetArgs::parse(&words(&["country"])).is_err());
        assert!(ConnectTargetArgs::parse(&words(&["country", "GB", "extra"])).is_err());
        assert!(ConnectTargetArgs::parse(&words(&["warp"])).is_err());
        let err = ConnectTargetArgs::parse(&words(&["warp"])).unwrap_err();
        assert_eq!(err.exit_code(), 2, "invalid arguments exit code");
    }
}
