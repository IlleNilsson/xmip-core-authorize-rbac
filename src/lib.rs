#![forbid(unsafe_code)]

//! The rbac authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: roles granted permissions on artifacts
//! (ADR-0050 section 5). A [`Role`] permits and forbids actions on artifacts
//! named by pattern — `Billing*`, `partner-x`, `*` — and the identity's roles
//! come from the facts: every evidence entry the gate recorded under [`ROLE`]
//! on either layer of the record, one role each.
//! A role the identity carries and this policy does not define grants
//! nothing.
//!
//! What a held role forbids is refused, naming the role; failing that, what
//! any held role permits is allowed; failing both, no opinion. A forbid beats
//! a permit whichever role carries it, because a role that says no was
//! written to say no.
//!
//! The `role` technology computes roles from a store and cannot put them on
//! the facts through `decide(&IdentityFacts, ..)`; until the capability
//! carries them, what this policy reads is what the gate recorded.

use authorize::pattern::matches;
use authorize::{Action, Attempt, Authorizer, Decision};
use context::IdentityFacts;
use xcore::Layer;

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "rbac";

/// The evidence name roles are read from.
pub const ROLE: &str = "role";

/// One action, or any, on artifacts named by pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Permission {
    action: Option<Action>,
    artifact: String,
}

impl Permission {
    /// One action on artifacts matching the pattern.
    #[must_use]
    pub fn to(action: Action, artifact: impl Into<String>) -> Self {
        Self {
            action: Some(action),
            artifact: artifact.into(),
        }
    }

    /// Any action on artifacts matching the pattern.
    #[must_use]
    pub fn any(artifact: impl Into<String>) -> Self {
        Self {
            action: None,
            artifact: artifact.into(),
        }
    }

    fn covers(&self, attempt: &Attempt) -> bool {
        self.action.is_none_or(|action| action == attempt.action)
            && matches(&self.artifact, &attempt.artifact)
    }
}

/// A role: what it permits, and what it forbids.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Role {
    name: String,
    permits: Vec<Permission>,
    forbids: Vec<Permission>,
}

impl Role {
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            permits: Vec::new(),
            forbids: Vec::new(),
        }
    }

    #[must_use]
    pub fn permits(mut self, permission: Permission) -> Self {
        self.permits.push(permission);
        self
    }

    #[must_use]
    pub fn forbids(mut self, permission: Permission) -> Self {
        self.forbids.push(permission);
        self
    }
}

/// The roles this deployment defines.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Rbac {
    roles: Vec<Role>,
}

impl Rbac {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a role.
    #[must_use]
    pub fn role(mut self, role: Role) -> Self {
        self.roles.push(role);
        self
    }

    /// The roles the record says this identity holds: every [`ROLE`]
    /// evidence entry on either layer, one role each, sorted, each once.
    #[must_use]
    pub fn held_by(identity: &IdentityFacts) -> Vec<String> {
        let mut roles: Vec<String> = identity
            .held()
            .flat_map(|held| held.evidence_values(ROLE))
            .filter(|role| !role.is_empty())
            .map(ToString::to_string)
            .collect();

        roles.sort();
        roles.dedup();
        roles
    }
}

impl Authorizer for Rbac {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let held = Self::held_by(identity);
        let roles = self.roles.iter().filter(|role| held.contains(&role.name));
        let mut permitted = false;

        for role in roles {
            if role.forbids.iter().any(|forbid| forbid.covers(attempt)) {
                return Some(Decision::denied(
                    NAME,
                    format!(
                        "role '{}' forbids {} on '{}'",
                        role.name, attempt.action, attempt.artifact
                    ),
                ));
            }

            permitted |= role.permits.iter().any(|permit| permit.covers(attempt));
        }

        permitted.then_some(Decision::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, mechanism};

    fn holding(roles: &[&str]) -> IdentityFacts {
        let identity = roles.iter().fold(
            AuthenticatedIdentity::new(
                mechanism::oauth2(),
                "sub=alice",
                Established::Passed,
                Verified::Proven,
            ),
            |identity, role| identity.with_evidence(ROLE, *role),
        );

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn rbac() -> Rbac {
        Rbac::new()
            .role(
                Role::named("shipper")
                    .permits(Permission::to(Action::Receive, "partner-*"))
                    .permits(Permission::to(Action::Send, "Shipping")),
            )
            .role(Role::named("auditor").forbids(Permission::any("Billing*")))
            .role(Role::named("operator").permits(Permission::any("*")))
    }

    #[test]
    fn what_a_held_role_permits_is_allowed() {
        let decision = rbac().decide(
            &holding(&["shipper"]),
            &Attempt::new(Action::Receive, "partner-x"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(rbac().name(), "rbac");
        assert_eq!(rbac().layer(), Layer::Transport);
    }

    #[test]
    fn what_a_held_role_forbids_is_refused_naming_the_role_whatever_another_permits() {
        // The operator may do anything; the auditor may not touch Billing;
        // an identity holding both is refused, because a role that says no
        // was written to say no.
        let decision = rbac()
            .decide(
                &holding(&["operator", "auditor"]),
                &Attempt::new(Action::Send, "Billing"),
            )
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by rbac: role 'auditor' forbids send on 'Billing'"
        );
    }

    #[test]
    fn a_role_that_neither_permits_nor_forbids_this_is_no_opinion() {
        assert_eq!(
            rbac().decide(
                &holding(&["shipper"]),
                &Attempt::new(Action::Send, "Billing")
            ),
            None
        );
        assert_eq!(
            rbac().decide(
                &holding(&["visitor"]),
                &Attempt::new(Action::Send, "Shipping")
            ),
            None,
            "a role this policy does not define grants nothing"
        );
        assert_eq!(
            rbac().decide(&holding(&[]), &Attempt::new(Action::Send, "Shipping")),
            None
        );
    }

    #[test]
    fn roles_are_read_from_both_layers_and_a_pattern_names_artifacts() {
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            holding(&["shipper"]).transport,
            Some(
                AuthenticatedIdentity::new(
                    mechanism::edi_x12_interchange(),
                    "ISA06=PARTNERX",
                    Established::Detected,
                    Verified::Claimed,
                )
                .with_evidence(ROLE, "operator"),
            ),
        );

        assert_eq!(Rbac::held_by(&facts), vec!["operator", "shipper"]);
        assert_eq!(
            rbac().decide(&facts, &Attempt::new(Action::Process, "Approval")),
            Some(Decision::Allowed)
        );
    }
}
