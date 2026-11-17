// SPDX-License-Identifier: MIT
// TEAL: ticket session-binding selection and Netlink wire fields.
//
// This self-contained module is intended to be integrated into teald.
// It is NOT a drop-in replacement for src/teald/src/netlink.rs: the
// current TICKET_ADD writer and ApprovedTicket definitions were not provided.
//
// Contract: kernel/security/teal/teal_lsm.c (session-bound v2)
//   TEAL_ATTR_AUDIT_SESSIONID = 34 (u32)
//   TEAL_ATTR_LOGINUID       = 35 (u32)
//   TEAL_TICKET_FLG_SESSION_BOUND = 1 << 5
// The kernel rejects incomplete binding or attributes without the flag.

pub const TEAL_ATTR_AUDIT_SESSIONID: u16 = 34;
pub const TEAL_ATTR_LOGINUID: u16 = 35;

pub const TEAL_TICKET_FLG_SILENT_IO: u32 = 1 << 0;
pub const TEAL_TICKET_FLG_INHERIT: u32 = 1 << 1;
pub const TEAL_TICKET_FLG_NAMELESS_IPC: u32 = 1 << 2;
pub const TEAL_TICKET_FLG_SESSION_BOUND: u32 = 1 << 5;

const INVALID_AUDIT_ID: u32 = u32::MAX;

/// Whether a ticket requires a PAM-authenticated login session.
///
/// `Required` must be chosen for a policy evaluation which depends on
/// registered login/session context (e.g., a role or SSH-login condition).
/// `IfRegistered` is appropriate for regular tickets that may also be issued
/// for background/system service processes.
/// `Independent` intentionally produces no session binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    Required,
    IfRegistered,
    Independent,
}

/// Kernel-originated identifiers and the result of the teald PAM registry
/// lookup for THIS request. Do not substitute the request EUID for loginuid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginContext {
    pub audit_session_id: Option<u32>,
    pub loginuid: Option<u32>,
    /// RegisteredSession.uid returned by check_registered_session().
    /// None means that this request has not been verified as a registered login.
    pub registered_loginuid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBoundIds {
    pub audit_session_id: u32,
    pub loginuid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketSessionWire {
    /// Complete ticket flags to send as TEAL_ATTR_FLAGS.
    pub flags: u32,
    /// When Some, BOTH attributes MUST be transmitted in TICKET_ADD.
    pub bound_ids: Option<SessionBoundIds>,
}

impl TicketSessionWire {
    /// Return the exact numeric attributes expected by kernel v2.
    /// The actual `neli::Nlattr` construction remains in the existing writer.
    pub fn netlink_u32_fields(self) -> Option<[(u16, u32); 2]> {
        self.bound_ids.map(|ids| {
            [
                (TEAL_ATTR_AUDIT_SESSIONID, ids.audit_session_id),
                (TEAL_ATTR_LOGINUID, ids.loginuid),
            ]
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBindingError {
    /// Session binding bit should be set by this helper, not independently.
    BindingBitAlreadySet,
    /// One of the kernel-originated pair is missing.
    PartialSessionIdentity,
    /// Linux Audit uses u32::MAX for unset identities.
    InvalidSessionIdentity,
    /// The rule requires a login but no valid registered login is present.
    RegisteredLoginRequired,
    /// Registry says this is a different login UID.
    LoginUidMismatch,
}

/// Choose and validate session-binding fields BEFORE TICKET_ADD.
///
/// - SILENT_IO / NAMELESS_IPC are log-storm suppression tickets; they remain
///   unbound, even in a login session. Existing Self-Baking behaviour is intact.
/// - For an ordinary interactive ticket, bind only after verifying the
///   kernel-supplied session identity against the PAM session registry.
/// - For a rule dependent on the registered login, choose `Required` so
///   failure cannot silently downgrade to an unbound ticket.
/// - `Independent` is for deliberate non-login workloads, not a fallback
///   for invalid or mismatched session credentials.
pub fn select_ticket_session_binding(
    existing_flags: u32,
    mode: BindingMode,
    ctx: LoginContext,
) -> Result<TicketSessionWire, SessionBindingError> {
    if existing_flags & TEAL_TICKET_FLG_SESSION_BOUND != 0 {
        return Err(SessionBindingError::BindingBitAlreadySet);
    }

    // These two special flags describe intentionally unprotected resources.
    // Preserve their pre-existing Self-Baking / log suppression semantics.
    if existing_flags & (TEAL_TICKET_FLG_SILENT_IO | TEAL_TICKET_FLG_NAMELESS_IPC) != 0 {
        return Ok(TicketSessionWire {
            flags: existing_flags,
            bound_ids: None,
        });
    }

    if mode == BindingMode::Independent {
        return Ok(TicketSessionWire {
            flags: existing_flags,
            bound_ids: None,
        });
    }

    let (sid, loginuid) = match (ctx.audit_session_id, ctx.loginuid) {
        (None, None) => {
            return if mode == BindingMode::Required {
                Err(SessionBindingError::RegisteredLoginRequired)
            } else {
                Ok(TicketSessionWire {
                    flags: existing_flags,
                    bound_ids: None,
                })
            };
        }
        (Some(sid), Some(loginuid)) => (sid, loginuid),
        _ => return Err(SessionBindingError::PartialSessionIdentity),
    };

    if sid == INVALID_AUDIT_ID || loginuid == INVALID_AUDIT_ID {
        return Err(SessionBindingError::InvalidSessionIdentity);
    }

    match ctx.registered_loginuid {
        Some(registered) if registered == loginuid => Ok(TicketSessionWire {
            flags: existing_flags | TEAL_TICKET_FLG_SESSION_BOUND,
            bound_ids: Some(SessionBoundIds {
                audit_session_id: sid,
                loginuid,
            }),
        }),
        Some(_) => Err(SessionBindingError::LoginUidMismatch),
        None if mode == BindingMode::Required => Err(SessionBindingError::RegisteredLoginRequired),
        None => Ok(TicketSessionWire {
            flags: existing_flags,
            bound_ids: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered() -> LoginContext {
        LoginContext {
            audit_session_id: Some(42),
            loginuid: Some(1000),
            registered_loginuid: Some(1000),
        }
    }

    #[test]
    fn normal_ticket_is_bound_to_registered_session() {
        let wire =
            select_ticket_session_binding(0, BindingMode::IfRegistered, registered()).unwrap();
        assert_eq!(wire.flags, TEAL_TICKET_FLG_SESSION_BOUND);
        assert_eq!(wire.netlink_u32_fields(), Some([(34, 42), (35, 1000)]));
    }

    #[test]
    fn required_login_uses_same_binding() {
        let wire = select_ticket_session_binding(0, BindingMode::Required, registered()).unwrap();
        assert!(wire.bound_ids.is_some());
    }

    #[test]
    fn silent_io_remains_unbound_and_inherited() {
        let flags = TEAL_TICKET_FLG_SILENT_IO | TEAL_TICKET_FLG_INHERIT;
        let wire =
            select_ticket_session_binding(flags, BindingMode::Required, registered()).unwrap();
        assert_eq!(wire.flags, flags);
        assert_eq!(wire.netlink_u32_fields(), None);
    }

    #[test]
    fn nameless_ipc_remains_unbound() {
        let flags = TEAL_TICKET_FLG_NAMELESS_IPC;
        let wire =
            select_ticket_session_binding(flags, BindingMode::IfRegistered, registered()).unwrap();
        assert_eq!(wire.flags, flags);
        assert!(wire.bound_ids.is_none());
    }

    #[test]
    fn background_service_remains_unbound_when_allowed() {
        let wire = select_ticket_session_binding(
            0,
            BindingMode::IfRegistered,
            LoginContext {
                audit_session_id: None,
                loginuid: None,
                registered_loginuid: None,
            },
        )
        .unwrap();
        assert_eq!(wire.flags, 0);
        assert_eq!(wire.netlink_u32_fields(), None);
    }

    #[test]
    fn required_login_never_downgrades_to_unbound() {
        let err = select_ticket_session_binding(
            0,
            BindingMode::Required,
            LoginContext {
                audit_session_id: Some(42),
                loginuid: Some(1000),
                registered_loginuid: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, SessionBindingError::RegisteredLoginRequired);
    }

    #[test]
    fn rejects_partial_session_identity() {
        let err = select_ticket_session_binding(
            0,
            BindingMode::IfRegistered,
            LoginContext {
                audit_session_id: Some(42),
                loginuid: None,
                registered_loginuid: Some(1000),
            },
        )
        .unwrap_err();
        assert_eq!(err, SessionBindingError::PartialSessionIdentity);
    }

    #[test]
    fn rejects_unset_audit_id() {
        let err = select_ticket_session_binding(
            0,
            BindingMode::IfRegistered,
            LoginContext {
                audit_session_id: Some(u32::MAX),
                loginuid: Some(1000),
                registered_loginuid: Some(1000),
            },
        )
        .unwrap_err();
        assert_eq!(err, SessionBindingError::InvalidSessionIdentity);
    }

    #[test]
    fn rejects_registered_uid_mismatch() {
        let err = select_ticket_session_binding(
            0,
            BindingMode::IfRegistered,
            LoginContext {
                audit_session_id: Some(42),
                loginuid: Some(1000),
                registered_loginuid: Some(2000),
            },
        )
        .unwrap_err();
        assert_eq!(err, SessionBindingError::LoginUidMismatch);
    }

    #[test]
    fn independent_ticket_has_no_binding() {
        let wire =
            select_ticket_session_binding(0, BindingMode::Independent, registered()).unwrap();
        assert!(wire.bound_ids.is_none());
    }

    #[test]
    fn protects_against_manual_binding_flag_without_fields() {
        let err = select_ticket_session_binding(
            TEAL_TICKET_FLG_SESSION_BOUND,
            BindingMode::IfRegistered,
            registered(),
        )
        .unwrap_err();
        assert_eq!(err, SessionBindingError::BindingBitAlreadySet);
    }
}
