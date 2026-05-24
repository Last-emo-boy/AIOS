use crate::model::{RiskClass, SemanticToolCall};

pub trait ExecutionStep {
    fn step_id(&self) -> &str;
    fn call(&self) -> &SemanticToolCall;
    fn planner_risk_hints(&self) -> Vec<RiskClass>;
    fn rollback_required(&self) -> bool;
}

impl<T: ExecutionStep + ?Sized> ExecutionStep for &T {
    fn step_id(&self) -> &str {
        (*self).step_id()
    }

    fn call(&self) -> &SemanticToolCall {
        (*self).call()
    }

    fn planner_risk_hints(&self) -> Vec<RiskClass> {
        (*self).planner_risk_hints()
    }

    fn rollback_required(&self) -> bool {
        (*self).rollback_required()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionStepSnapshot {
    step_id: String,
    call: SemanticToolCall,
    planner_risk_hints: Vec<RiskClass>,
    rollback_required: bool,
}

impl ExecutionStepSnapshot {
    pub fn from_step<T: ExecutionStep + ?Sized>(step: &T) -> Self {
        Self {
            step_id: step.step_id().to_string(),
            call: step.call().clone(),
            planner_risk_hints: step.planner_risk_hints(),
            rollback_required: step.rollback_required(),
        }
    }

    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    pub fn call(&self) -> &SemanticToolCall {
        &self.call
    }

    pub fn planner_risk_hints(&self) -> &[RiskClass] {
        &self.planner_risk_hints
    }

    pub fn rollback_required(&self) -> bool {
        self.rollback_required
    }
}

impl ExecutionStep for ExecutionStepSnapshot {
    fn step_id(&self) -> &str {
        self.step_id()
    }

    fn call(&self) -> &SemanticToolCall {
        self.call()
    }

    fn planner_risk_hints(&self) -> Vec<RiskClass> {
        self.planner_risk_hints().to_vec()
    }

    fn rollback_required(&self) -> bool {
        self.rollback_required()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StepFixture {
        call: SemanticToolCall,
    }

    impl ExecutionStep for StepFixture {
        fn step_id(&self) -> &str {
            "step-1"
        }

        fn call(&self) -> &SemanticToolCall {
            &self.call
        }

        fn planner_risk_hints(&self) -> Vec<RiskClass> {
            vec![RiskClass::ReadOnly]
        }

        fn rollback_required(&self) -> bool {
            false
        }
    }

    #[test]
    fn snapshots_execution_step_without_runtime_owner_dependency() {
        let fixture = StepFixture {
            call: SemanticToolCall::new("svc.status", vec![("service", "agentd")]),
        };
        let snapshot = ExecutionStepSnapshot::from_step(&fixture);

        assert_eq!(snapshot.step_id(), "step-1");
        assert_eq!(snapshot.call().name, "svc.status");
        assert_eq!(snapshot.planner_risk_hints(), &[RiskClass::ReadOnly]);
        assert!(!snapshot.rollback_required());
    }
}
