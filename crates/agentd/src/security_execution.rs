pub use security_execution_crate::*;

#[cfg(test)]
mod compatibility {
    use super::effect_envelope::{EffectEnvelope, EffectEnvelopeState};
    use super::policy::{PolicyDecision, PolicyDecisionKind};
    use super::source_to_sink::{ContentSource, SinkDescriptor, SourceToSinkRequest};
    use crate::api::{RiskClass, SemanticToolCall};

    #[test]
    fn facade_exports_effect_envelope_paths() {
        let decision = PolicyDecision {
            kind: PolicyDecisionKind::Allow,
            risk: RiskClass::ReadOnly,
            reason: "compatibility smoke".to_string(),
        };
        let envelope = EffectEnvelope::draft(
            "run-compat",
            "step-compat",
            "svc.status",
            vec![("service".to_string(), "agentd".to_string())],
            decision,
        )
        .expect("draft");

        assert_eq!(envelope.state, EffectEnvelopeState::Draft);
    }

    #[test]
    fn facade_exports_source_to_sink_paths() {
        let source = ContentSource::external_content("content-compat").expect("source");
        let sink = SinkDescriptor::for_tool(
            "svc.restart",
            RiskClass::ExecuteWithConfirmation,
            "agentd",
            vec![("service".to_string(), "agentd".to_string())],
        )
        .expect("sink");
        let request =
            SourceToSinkRequest::new("run-compat", "step-compat", "operator", source, sink)
                .expect("request");

        assert_eq!(request.sink.tool, "svc.restart");
    }

    #[test]
    fn facade_exports_tool_router_paths() {
        let routed = super::tools::ToolRouter
            .route(&SemanticToolCall::new("svc.status", vec![("service", "agentd")]))
            .expect("route");

        assert_eq!(routed.risk, RiskClass::ReadOnly);
    }
}
