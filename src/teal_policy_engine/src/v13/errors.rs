use thiserror::Error;

#[derive(Debug, Clone)]
pub enum ValidateErrorKind {
    Schema,
    Io,
    JsonParse,
    Semantic,
}

#[derive(Debug, Error, Clone)]
#[error("{kind:?}: {message}")]
pub struct ValidateError {
    pub kind: ValidateErrorKind,
    pub message: String,
}

impl ValidateError {
    pub fn new(kind: ValidateErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("syntax error: {0}")]
    Json(String),
    #[error("unsupported version error: {0}")]
    UnsupportedVersion(String),
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(String),
    #[error("duplicate role name: {0}")]
    DuplicateRoleName(String),
    #[error("invalid role name: {name} ({reason})")]
    InvalidRoleName { name: String, reason: String },
    #[error("semantic error: {0}")]
    Semantic(String),
    #[error("missing field error: {0}")]
    MissingField(&'static str),
    #[error("invalid field error: {0} : {1}")]
    InvalidField(&'static str, String),
    #[error("invalid object path: {0}")]
    InvalidObjectPath(String),
    #[error("unsupported action error: {0}")]
    UnknownAction(String),
    #[error("unknown role error: {0}")]
    UnknownRole(String),
    #[error("unknown role `{role}` referenced in assignment ({context})")]
    UnknownRoleInAssignment {
        role: String,
        context: AssignmentContext,
    },
    #[error("empty role set in assignment ({context})")]
    EmptyRoleSetInAssignment {
        context: AssignmentContext,
    },
    #[error("missing assignment target")]
    MissingAssignmentTarget,
    #[error("ambiguous assignment target")]
    AmbiguousAssignmentTarget,
    #[error("invalid assignment target: {kind} (uid={uid:?}, user={user:?})")]
    InvalidAssignmentTarget {
        kind: AssignmentKind,
        uid: Option<u32>,
        user: Option<String>,
    },

    #[error("missing group assignment target")]
    MissingGroupAssignmentTarget,
    #[error("ambiguous group assignment target")]
    AmbiguousGroupAssignmentTarget,
    #[error("invalid group assignment target: {kind} (gid={gid:?}, group={group:?})")]
    InvalidGroupAssignmentTarget {
        kind: AssignmentKind,
        gid: Option<u32>,
        group: Option<String>,
    },

    // --- Role references ---
    #[error("unknown role referenced: {role} (context: {context})")]
    UnknownRoleReferenced { role: String, context: String },

    #[error("path normalize error: {0}")]
    PathNormalize(String),
    #[error("rule `{rule_id}`: mpa_threshold is required when effect is `need_approval`")]
    MissingMpaThreshold {
        rule_id: String,
    },
    #[error("rule `{rule_id}`: invalid mpa_threshold (must be >= 1)")]
    InvalidMpaThreshold {
        rule_id: String,
    },

    #[error("invalid pre_approval_defaults: {0}")]
    InvalidPreApprovalDefaults(String),
    /// Field value is syntactically valid but semantically invalid.
    /// e.g. ttl_sec = 0, threshold = 0, negative ranges, out-of-bound values, etc.
    #[error("invalid value error: {0}")]
    InvalidValue(String),
}

#[derive(Debug, Clone, Default)]
pub struct CompileWarnings {
    pub warnings: Vec<String>,
}

impl CompileWarnings {
    pub fn warn<S: Into<String>>(&mut self, s: S) {
        self.warnings.push(s.into());
    }

    pub fn extend(&mut self, other: CompileWarnings) {
        self.warnings.extend(other.warnings);
    }
}

#[derive(Debug, Clone)]
pub enum AssignmentContext {
    User { user: String },
    Uid { uid: u32 },
    Group { group: String },
    Gid { gid: u32 },
}

impl std::fmt::Display for AssignmentContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssignmentContext::User { user } => write!(f, "user={}", user),
            AssignmentContext::Uid { uid } => write!(f, "uid={}", uid),
            AssignmentContext::Group { group } => write!(f, "group={}", group),
            AssignmentContext::Gid { gid } => write!(f, "gid={}", gid),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AssignmentKind {
    MissingTarget,   // both None
    AmbiguousTarget, // both Some
    EmptyName,       // Some("")
}

impl std::fmt::Display for AssignmentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssignmentKind::MissingTarget => write!(f, "missing target"),
            AssignmentKind::AmbiguousTarget => write!(f, "ambiguous target"),
            AssignmentKind::EmptyName => write!(f, "empty name target"),
        }
    }
}
