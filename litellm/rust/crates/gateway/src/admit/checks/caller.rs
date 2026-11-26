use axum::http::request::Parts;
use litellm_config::GeneralSettings;
use litellm_gateway_auth_core::{Credential, Via};

use super::{Admit, Authentication, Reason, Refused, head::TEAM_HEADER};

/// Each caller the core hands back is matched by name, with no catch-all, so a caller the native
/// host learns to serve does not compile here until it is named native or not. A credential the
/// core did not authenticate is over the error's name. A JWT is checked against its scope mappings
/// only for the model the request names, which the core is not handed before the body is read.
/// Only the JWT path reads the team header, and Python code after auth reads it beside a key, so a
/// key that sends one stays with Python, a key a JWT maps to included.
pub(super) fn caller(
    admit: &Admit,
    request: &Parts,
    authentication: &Authentication,
) -> Option<Reason> {
    let team_header = || {
        request
            .headers
            .contains_key(TEAM_HEADER)
            .then(|| Reason::new(Refused::Headers, TEAM_HEADER))
    };
    let scope_mappings = || {
        scope_mappings_enforced(&admit.config.general_settings)
            .then(|| Reason::new(Refused::Settings, "enforce_scope_based_access"))
    };
    match authentication {
        Ok(caller) => match &caller.credential {
            Credential::MasterKey
            | Credential::Key {
                via: Via::OwnToken, ..
            } => team_header(),
            Credential::Key {
                via: Via::MappedJwt(_),
                ..
            } => team_header().or_else(scope_mappings),
            Credential::Jwt { .. } => scope_mappings(),
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
