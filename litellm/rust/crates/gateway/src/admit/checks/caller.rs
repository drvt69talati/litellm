use litellm_config::GeneralSettings;
use litellm_gateway_auth_core::{Credential, Via};

use super::{Admit, Authentication, Reason, Refused};

/// Each caller the core hands back is matched by name, with no catch-all, so a caller the native
/// host learns to serve does not compile here until it is named native or not. A credential the
/// core did not authenticate is over the error's name. A JWT is checked against its scope mappings
/// only for the model the request names, which the core is not handed before the body is read.
pub(super) fn caller(admit: &Admit, authentication: &Authentication) -> Option<Reason> {
    match authentication {
        Ok(caller) => match &caller.credential {
            Credential::MasterKey
            | Credential::Key {
                via: Via::OwnToken, ..
            } => None,
            Credential::Key {
                via: Via::MappedJwt(_),
                ..
            }
            | Credential::Jwt { .. } => scope_mappings_enforced(&admit.config.general_settings)
                .then(|| Reason::new(Refused::Settings, "enforce_scope_based_access")),
        },
        Err(error) => Some(Reason::new(
            Refused::Credential,
            <&'static str>::from(error),
        )),
    }
}

fn scope_mappings_enforced(general: &GeneralSettings) -> bool {
    general.litellm_jwtauth.as_ref().is_some_and(|jwt| {
        jwt.enforce_scope_based_access
            && jwt
                .scope_mappings
                .as_deref()
                .is_some_and(|mappings| !mappings.is_empty())
    })
}
