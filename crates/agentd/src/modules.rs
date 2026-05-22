#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Planner,
    Policy,
    Capability,
    ToolRouter,
    Audit,
    Rollback,
    ModelBroker,
    Tui,
}

impl ModuleKind {
    pub const ALL: [ModuleKind; 8] = [
        ModuleKind::Planner,
        ModuleKind::Policy,
        ModuleKind::Capability,
        ModuleKind::ToolRouter,
        ModuleKind::Audit,
        ModuleKind::Rollback,
        ModuleKind::ModelBroker,
        ModuleKind::Tui,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ModuleKind::Planner => "planner",
            ModuleKind::Policy => "policy",
            ModuleKind::Capability => "capability",
            ModuleKind::ToolRouter => "tool_router",
            ModuleKind::Audit => "audit",
            ModuleKind::Rollback => "rollback",
            ModuleKind::ModelBroker => "model_broker",
            ModuleKind::Tui => "tui",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleState {
    StubReady,
    Error(String),
}

impl ModuleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleState::StubReady => "stub_ready",
            ModuleState::Error(_) => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleStatus {
    pub kind: ModuleKind,
    pub state: ModuleState,
}

impl ModuleStatus {
    pub fn stub_ready(kind: ModuleKind) -> Self {
        Self {
            kind,
            state: ModuleState::StubReady,
        }
    }
}
