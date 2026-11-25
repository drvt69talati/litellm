//! The caller a host serves once authentication is over. It is the only thing a host carries past
//! authentication, so everything a host later asks about the caller is answered here, from what
//! the key path read.

use std::convert::Infallible;

use litellm_config::LitellmRole;
use serde_json::{Map, Value};

use crate::{
    Affiliation, KeyHash, Rows,
    authn::key::KeyRecord,
    identity::{
        jwt::{JwtIdentity, ManagedAgent},
        key::{KeyContext, KeyIdentity},
    },
    outcome::Identity,
};

/// A host's key row that keeps the record the key path read it with, which gives a caller its id
/// and role.
pub trait StoredKey {
    fn record(&self) -> &KeyRecord;
}

impl StoredKey for KeyRecord {
    fn record(&self) -> &KeyRecord {
        self
    }
}

impl StoredKey for Infallible {
    fn record(&self) -> &KeyRecord {
        match *self {}
    }
}

/// Who a request is served for: what it presented, what that belongs to, and the end user the
/// request names, which any credential can carry.
#[derive(Clone, Debug, PartialEq)]
pub struct Caller<R: Rows> {
    pub credential: Credential<R>,
    pub affiliation: Affiliation<R>,
    pub end_user: Option<R::EndUser>,
}

/// What a caller presented and the core verified.
#[derive(Clone, Debug, PartialEq)]
pub enum Credential<R: Rows> {
    MasterKey,
    Key {
        key: R::Key,
        via: Via,
    },
    Jwt {
        jwt: JwtStamp,
        actor: JwtActor<R::Agent>,
    },
}

/// How a virtual key was presented on the request.
#[derive(Clone, Debug, PartialEq)]
pub enum Via {
    OwnToken,
    MappedJwt(JwtStamp),
}

/// The verified JWT facts a credential carries past authentication, whether the JWT acts as
/// itself or mapped onto a virtual key.
#[derive(Clone, Debug, PartialEq)]
pub struct JwtStamp {
    pub claims: Map<String, Value>,
    pub user_email: Option<String>,
}

impl JwtStamp {
    fn from_value(claims: Value, user_email: Option<String>) -> Self {
        let claims = match claims {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        Self { claims, user_email }
    }
}

/// Who a JWT that acts as itself is acting as, with the role the core decided. Keeping managed
/// agents in their own variant ensures a managed agent cannot be represented as a proxy admin.
#[derive(Clone, Debug, PartialEq)]
pub enum JwtActor<A> {
    User { role: LitellmRole },
    RegisteredAgent { id: String, role: LitellmRole },
    ManagedAgent(ManagedAgent<A>),
}

impl<A> JwtActor<A> {
    pub fn role(&self) -> LitellmRole {
        match self {
            Self::User { role } | Self::RegisteredAgent { role, .. } => *role,
            Self::ManagedAgent(_) => LitellmRole::InternalUser,
        }
    }
}

/// An identity the core authenticated that no host serves a request for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NotACaller {
    #[error("no master key is configured, so no credential was checked")]
    NoMasterKey,
    #[error("the user auth route authenticates no caller")]
    UserAuthRoute,
    #[error("a cached admin key is served by the host that cached it")]
    CachedAdmin,
    #[error("an auto-registered JWT key is served by the host that registered it")]
    AutoRegisteredJwt,
}

impl<R: Rows> TryFrom<Identity<R>> for Caller<R> {
    type Error = NotACaller;

    fn try_from(identity: Identity<R>) -> Result<Self, NotACaller> {
        match identity {
            Identity::Key(KeyIdentity::MasterKey { end_user, .. }) => {
                Ok(Self::master_key(Some(end_user)))
            }
            Identity::Key(KeyIdentity::VirtualKey(context)) => {
                let KeyContext {
                    key,
                    affiliation,
                    end_user,
                } = *context;
                Ok(Self {
                    credential: Credential::Key {
                        key,
                        via: Via::OwnToken,
                    },
                    affiliation,
                    end_user: Some(end_user),
                })
            }
            Identity::MappedJwtKey(mapped, context) => {
                let KeyContext {
                    key,
                    affiliation,
                    end_user,
                } = *context;
                Ok(Self {
                    credential: Credential::Key {
                        key,
                        via: Via::MappedJwt(JwtStamp::from_value(mapped.claims, mapped.user_email)),
                    },
                    affiliation,
                    end_user: Some(end_user),
                })
            }
            Identity::Jwt(identity) => {
                let JwtIdentity {
                    claims,
                    is_proxy_admin,
                    user_email,
                    agent_id,
                    managed_agent,
                    affiliation,
                    end_user,
                    ..
                } = *identity;
                let role = if is_proxy_admin {
                    LitellmRole::ProxyAdmin
                } else {
                    LitellmRole::InternalUser
                };
                let actor = match managed_agent {
                    Some(agent) => JwtActor::ManagedAgent(agent),
                    None => match agent_id {
                        Some(id) => JwtActor::RegisteredAgent { id, role },
                        None => JwtActor::User { role },
                    },
                };
                Ok(Self {
                    credential: Credential::Jwt {
                        jwt: JwtStamp::from_value(claims, user_email),
                        actor,
                    },
                    affiliation,
                    end_user,
                })
            }
            Identity::Key(KeyIdentity::NoMasterKey { .. }) => Err(NotACaller::NoMasterKey),
            Identity::Key(KeyIdentity::UserAuthRoute) => Err(NotACaller::UserAuthRoute),
            Identity::Key(KeyIdentity::CachedAdmin { .. }) => Err(NotACaller::CachedAdmin),
            Identity::AutoRegisteredJwt(_) => Err(NotACaller::AutoRegisteredJwt),
        }
    }
}

impl<R: Rows> Caller<R> {
    /// The master key belongs to nothing, and can still name an end user.
    pub fn master_key(end_user: Option<R::EndUser>) -> Self {
        Self {
            credential: Credential::MasterKey,
            affiliation: Affiliation::nobody(),
            end_user,
        }
    }
}

impl<R: Rows<Key: StoredKey>> Caller<R> {
    /// The hash a key's row is stored under, which is the key's id wherever a host counts, caches
    /// or logs by it. Never the hash of the token the request presented, since a key a JWT maps
    /// to presents none. The key path refuses a key whose row has none, so only the master key
    /// and a JWT acting as itself have none.
    pub fn hash(&self) -> Option<&KeyHash> {
        match &self.credential {
            Credential::MasterKey | Credential::Jwt { .. } => None,
            Credential::Key { key, .. } => key.record().token.as_ref(),
        }
    }

    /// Admin is a role, never a kind of credential: the master key has it, a key has it when its
    /// row says so, and a JWT has it when the core resolved its actor as a proxy admin.
    // TODO: read the key owner's `user_role` once the key path returns it beside the owner's row,
    // as `UserAPIKeyAuth.user_role` is the owner's
    pub fn role(&self) -> LitellmRole {
        match &self.credential {
            Credential::MasterKey => LitellmRole::ProxyAdmin,
            Credential::Key { key, .. } if key.record().is_proxy_admin => LitellmRole::ProxyAdmin,
            Credential::Key { .. } => LitellmRole::InternalUser,
            Credential::Jwt { actor, .. } => actor.role(),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        Holder, Named, Token,
        authn::jwt::{KeyOrigin, MappedJwt},
        identity::jwt::{AgentMode, AutoRegisteredJwt, JwtIdentity, ManagedAgent},
    };

    #[derive(Clone, Debug, PartialEq)]
    struct Stored;

    impl Rows for Stored {
        type Key = KeyRecord;
        type User = String;
        type Team = String;
        type EndUser = String;
        type ObjectPermission = String;
        type Project = String;
        type Membership = String;
        type Org = String;
        type Agent = String;
    }

    fn stored(hash: &str) -> KeyRecord {
        KeyRecord {
            token: Some(KeyHash::new(hash)),
            ..KeyRecord::default()
        }
    }

    fn key(record: KeyRecord) -> Box<KeyContext<Stored>> {
        Box::new(KeyContext {
            key: record,
            affiliation: Affiliation::nobody(),
            end_user: "end-user".to_owned(),
        })
    }

    fn cached_admin() -> KeyIdentity<Stored> {
        KeyIdentity::CachedAdmin {
            key: KeyRecord {
                is_proxy_admin: true,
                ..stored("stored")
            },
            end_user: "end-user".to_owned(),
        }
    }

    fn mapped(origin: KeyOrigin) -> MappedJwt<String> {
        MappedJwt {
            claims: json!({"sub": "alice"}),
            user_email: Some("alice@example.com".to_owned()),
            end_user_id: None,
            origin,
            user: None,
        }
    }

    fn auto_registered_jwt() -> Identity<Stored> {
        Identity::AutoRegisteredJwt(Box::new(AutoRegisteredJwt {
            jwt: mapped(KeyOrigin::AutoRegistered {
                minted: true,
                org_id: None,
            }),
            key: stored("stored"),
            project: None,
        }))
    }

    fn jwt_identity(
        is_proxy_admin: bool,
        agent_id: Option<&str>,
        managed_agent: Option<ManagedAgent<String>>,
    ) -> Identity<Stored> {
        Identity::Jwt(Box::new(JwtIdentity {
            claims: json!({"sub": "alice"}),
            is_proxy_admin,
            user_id: Some("alice".to_owned()),
            user_email: Some("alice@example.com".to_owned()),
            team_id: None,
            org_id: None,
            end_user_id: Some("eu-1".to_owned()),
            agent_id: agent_id.map(str::to_owned),
            managed_agent,
            affiliation: Affiliation {
                holder: Holder::User(Named::Unstored("alice".to_owned())),
                org: None,
                project: None,
            },
            end_user: Some("end-user".to_owned()),
        }))
    }

    #[rstest]
    #[case::no_master_key(
        Identity::Key(KeyIdentity::NoMasterKey { token: Some(Token::new("anything")) }),
        NotACaller::NoMasterKey
    )]
    #[case::user_auth_route(Identity::Key(KeyIdentity::UserAuthRoute), NotACaller::UserAuthRoute)]
    #[case::cached_admin(Identity::Key(cached_admin()), NotACaller::CachedAdmin)]
    #[case::auto_registered_jwt(auto_registered_jwt(), NotACaller::AutoRegisteredJwt)]
    fn an_identity_no_host_serves_never_becomes_a_caller(
        #[case] identity: Identity<Stored>,
        #[case] expected: NotACaller,
    ) {
        assert_eq!(Caller::try_from(identity), Err(expected));
    }

    #[rstest]
    fn the_master_key_is_an_admin_with_no_row_that_keeps_the_requests_end_user() {
        let master = Identity::<Stored>::Key(KeyIdentity::MasterKey {
            hash: Token::new("sk-master").hash(),
            end_user: "end-user".to_owned(),
        });

        let caller = Caller::try_from(master).unwrap();

        assert_eq!(
            (
                caller.hash(),
                caller.role(),
                &caller.affiliation,
                caller.end_user.as_deref()
            ),
            (
                None,
                LitellmRole::ProxyAdmin,
                &Affiliation::nobody(),
                Some("end-user")
            )
        );
    }

    #[rstest]
    #[case::a_plain_key(false, LitellmRole::InternalUser)]
    #[case::a_key_its_row_calls_an_admin(true, LitellmRole::ProxyAdmin)]
    fn a_key_is_named_by_its_stored_hash_and_holds_the_role_its_row_says(
        #[case] is_proxy_admin: bool,
        #[case] role: LitellmRole,
    ) {
        let record = KeyRecord {
            is_proxy_admin,
            ..stored("stored")
        };
        let identity = Identity::Key(KeyIdentity::VirtualKey(key(record)));

        let caller = Caller::try_from(identity).unwrap();

        assert_eq!(
            (caller.hash(), caller.role()),
            (Some(&KeyHash::new("stored")), role)
        );
        assert!(matches!(
            caller.credential,
            Credential::Key {
                via: Via::OwnToken,
                ..
            }
        ));
    }

    #[rstest]
    #[case::a_plain_mapped_key(false, LitellmRole::InternalUser)]
    #[case::an_admin_mapped_key(true, LitellmRole::ProxyAdmin)]
    fn a_jwt_mapped_to_a_key_keeps_the_keys_stored_hash_and_the_jwt_stamp(
        #[case] is_proxy_admin: bool,
        #[case] role: LitellmRole,
    ) {
        let record = KeyRecord {
            is_proxy_admin,
            ..stored("mapped-hash")
        };
        let identity = Identity::MappedJwtKey(mapped(KeyOrigin::Mapping), key(record));

        let caller = Caller::try_from(identity).unwrap();

        assert_eq!(
            (caller.hash(), caller.role()),
            (Some(&KeyHash::new("mapped-hash")), role)
        );
        let Credential::Key {
            via: Via::MappedJwt(stamp),
            ..
        } = caller.credential
        else {
            panic!("expected a key presented via a mapped JWT");
        };
        assert_eq!(
            stamp.claims.get("sub").and_then(Value::as_str),
            Some("alice")
        );
        assert_eq!(stamp.user_email.as_deref(), Some("alice@example.com"));
    }

    #[rstest]
    #[case::a_plain_user_jwt(false, None, None, LitellmRole::InternalUser)]
    #[case::an_admin_user_jwt(true, None, None, LitellmRole::ProxyAdmin)]
    #[case::a_registered_agent_jwt(false, Some("agent-1"), None, LitellmRole::InternalUser)]
    #[case::an_admin_registered_agent_jwt(true, Some("agent-1"), None, LitellmRole::ProxyAdmin)]
    #[case::a_managed_agent_jwt_is_never_admin(
        true,
        Some("agent-2"),
        Some(ManagedAgent {
            mode: AgentMode::Autonomous,
            agent_id: "agent-2".to_owned(),
            user_id: None,
            row: "managed".to_owned(),
        }),
        LitellmRole::InternalUser
    )]
    fn a_jwt_acting_as_itself_has_no_key_hash_and_derives_its_role_from_its_actor(
        #[case] is_proxy_admin: bool,
        #[case] agent_id: Option<&str>,
        #[case] managed_agent: Option<ManagedAgent<String>>,
        #[case] expected_role: LitellmRole,
    ) {
        let caller =
            Caller::try_from(jwt_identity(is_proxy_admin, agent_id, managed_agent)).unwrap();

        assert_eq!(
            (caller.hash(), caller.role(), caller.end_user.as_deref()),
            (None, expected_role, Some("end-user"))
        );
        assert_eq!(
            caller.affiliation.holder,
            Holder::User(Named::Unstored("alice".to_owned()))
        );
        let Credential::Jwt { jwt, .. } = caller.credential else {
            panic!("expected a JWT credential");
        };
        assert_eq!(jwt.claims.get("sub").and_then(Value::as_str), Some("alice"));
        assert_eq!(jwt.user_email.as_deref(), Some("alice@example.com"));
    }
}
