#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::CertificatePayload;
use crate::msgs::handshake::SCTList;
use crate::msgs::handshake::ServerExtension;
use crate::sign;

use std::sync::Arc;

pub(super) struct ServerCertDetails {
    pub(super) cert_chain: CertificatePayload,
    pub(super) ocsp_response: Vec<u8>,
    pub(super) scts: Option<SCTList>,
}

impl ServerCertDetails {
    pub(super) fn new(
        cert_chain: CertificatePayload,
        ocsp_response: Vec<u8>,
        scts: Option<SCTList>,
    ) -> Self {
        Self {
            cert_chain,
            ocsp_response,
            scts,
        }
    }

    pub(super) fn scts(&self) -> impl Iterator<Item = &[u8]> {
        self.scts
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|payload| payload.0.as_slice())
    }
}

pub(super) struct ClientHelloDetails {
    pub(super) sent_extensions: Vec<ExtensionType>,
}

impl ClientHelloDetails {
    pub(super) fn new() -> Self {
        Self {
            sent_extensions: Vec::new(),
        }
    }

    pub(super) fn server_may_send_sct_list(&self) -> bool {
        self.sent_extensions
            .contains(&ExtensionType::SCT)
    }

    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &[ServerExtension],
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext in received_exts {
            let ext_type = ext.get_type();
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {:?}", ext_type);
                return true;
            }
        }

        false
    }
}

pub(super) struct ClientAuthDetails {
    pub(super) certkey: Option<Arc<sign::CertifiedKey>>,
    pub(super) signer: Option<Box<dyn sign::Signer>>,
    pub(super) auth_context: Option<Vec<u8>>,
}

impl ClientAuthDetails {
    pub(super) fn new() -> Self {
        Self {
            certkey: None,
            signer: None,
            auth_context: None,
        }
    }
}
