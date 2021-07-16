use crate::msgs::enums::ProtocolVersion;

/// A TLS protocl version supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the [`ALL_VERSIONS`] array, as well as individually as [`TLS12`]
/// and [`TLS13`].
#[derive(Debug, PartialEq)]
pub struct SupportedProtocolVersion {
    /// The TLS enumeration naming this version.
    pub version: ProtocolVersion,
    is_private: (),
}

/// TLS1.2
#[cfg(feature = "tls12")]
pub static TLS12: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_2,
    is_private: (),
};

/// TLS1.3
pub static TLS13: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_3,
    is_private: (),
};

/// A list of all the protocol versions supported by rustls.
pub static ALL_VERSIONS: &[&SupportedProtocolVersion] = &[
    &TLS13,
    #[cfg(feature = "tls12")]
    &TLS12,
];

/// The version configuration that an application should use by default.
///
/// This will be [`ALL_VERSIONS`] for now, but gives space in the future
/// to remove a version from here and require users to opt-in to older
/// versions.
pub static DEFAULT_VERSIONS: &[&SupportedProtocolVersion] = ALL_VERSIONS;

#[derive(Debug, Clone)]
pub(crate) struct EnabledVersions {
    #[cfg(feature = "tls12")]
    tls12: Option<&'static SupportedProtocolVersion>,
    tls13: Option<&'static SupportedProtocolVersion>,
}

impl EnabledVersions {
    pub(crate) fn new(versions: &[&'static SupportedProtocolVersion]) -> Self {
        let mut ev = Self {
            #[cfg(feature = "tls12")]
            tls12: None,
            tls13: None,
        };

        for v in versions {
            match v.version {
                #[cfg(feature = "tls12")]
                ProtocolVersion::TLSv1_2 => ev.tls12 = Some(v),
                ProtocolVersion::TLSv1_3 => ev.tls13 = Some(v),
                _ => {}
            }
        }

        ev
    }

    pub(crate) fn contains(&self, version: ProtocolVersion) -> bool {
        match version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => self.tls12.is_some(),
            ProtocolVersion::TLSv1_3 => self.tls13.is_some(),
            _ => false,
        }
    }
}
