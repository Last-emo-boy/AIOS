use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use agentd::{
    api::{RiskClass, SemanticToolCall},
    audit::{AuditEvent, AuditEventType, AuditJournal},
    lifecycle::{Agentd, LifecycleConfig},
    policy::{ApprovalToken, PolicyEvaluator, PolicyRequest, stable_parameter_hash},
    recovery::RecoveryReconciler,
    rollback::{content_hash, WriteDiffExecutor, WriteRequest},
    sandbox::{SandboxCompiler, SandboxExecutor, SandboxOperation},
    service_recovery::{RestartApproval, ServiceFixture, ServiceRecoveryWorkflow},
    tui::{ApprovalDecision, build_demo_session},
};

fn main() {
    let mut agentd = Agentd::new(LifecycleConfig::default());
    agentd.start();

    let args: Vec<String> = env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("--health") => {
            println!("{}", agentd.health_report().to_json());
            Ok(())
        }
        Some("--simulate-error") => {
            agentd.record_error("simulated controlled agentd error");
            println!("{}", agentd.health_report().to_json());
            Ok(())
        }
        Some("--plan-preview") => {
            let intent = args.get(2).map(String::as_str).unwrap_or("inspect system");
            let plan = agentd.plan(intent);
            println!("{}", plan.to_json());
            Ok(())
        }
        Some("--invoke-stub") => {
            let call = SemanticToolCall::new("svc.status", vec![("service", "agentd")]);
            let effect = agentd.invoke(call);
            println!("{}", effect.to_json());
            Ok(())
        }
        Some("--route-tool") => {
            let Some(tool) = args.get(2) else {
                return finish(Err("missing tool name".to_string()));
            };
            let params = match parse_params(&args[3..]) {
                Ok(params) => params,
                Err(error) => return finish(Err(error)),
            };
            let call = SemanticToolCall {
                name: tool.to_string(),
                params,
            };
            match agentd.route_tool(&call) {
                Ok(routed) => {
                    println!("{}", routed.to_json());
                    Ok(())
                }
                Err(rejection) => {
                    println!("{}", rejection.to_json());
                    Err(rejection.reason)
                }
            }
        }
        Some("--audit-demo") => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or(".workflow/artifacts/audit/demo.jsonl");
            run_audit_demo(path)
        }
        Some("--recovery-demo") => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or(".workflow/artifacts/recovery/demo.jsonl");
            run_recovery_demo(path)
        }
        Some("--policy-demo") => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or(".workflow/artifacts/policy/demo.jsonl");
            run_policy_demo(&agentd, path)
        }
        Some("--sandbox-demo") => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or(".workflow/artifacts/sandbox/demo.jsonl");
            run_sandbox_demo(&agentd, path)
        }
        Some("--write-diff-demo") => {
            let root = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".workflow/artifacts/rollback/demo"));
            run_write_diff_demo(&agentd, root)
        }
        Some("--service-recovery-demo") => {
            let approval = match args.get(2).map(String::as_str) {
                Some("approved") | Some("approve") | None => RestartApproval::Approved,
                Some("denied") | Some("deny") => RestartApproval::Denied,
                Some(other) => return finish(Err(format!("unknown restart approval: {other}"))),
            };
            let path = args
                .get(3)
                .map(String::as_str)
                .unwrap_or(".workflow/artifacts/service-recovery/demo.jsonl");
            run_service_recovery_demo(path, approval)
        }
        Some("--audit-show") => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or(".workflow/artifacts/service-recovery/demo.jsonl");
            let run_id = args.get(3).map(String::as_str);
            run_audit_show(path, run_id)
        }
        Some("--tui-demo") => {
            let intent = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("recover local service");
            let approval = match args.get(3).map(String::as_str) {
                Some(value) => match parse_approval(value) {
                    Ok(approval) => approval,
                    Err(error) => return finish(Err(error)),
                },
                None => ApprovalDecision::Approved,
            };
            let session = build_demo_session(&agentd, intent, approval);
            print!("{}", session.render());
            Ok(())
        }
        Some("--tui-audit-json") => {
            let intent = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("recover local service");
            let session = build_demo_session(&agentd, intent, ApprovalDecision::Denied);
            println!("{}", session.audit_json());
            Ok(())
        }
        Some("--tui-interactive") => run_interactive(&agentd),
        Some("--reap-once") => {
            let reaped = agentd.reap_children_once();
            println!("{{\"reaped_children\":{reaped}}}");
            Ok(())
        }
        Some(flag) => Err(format!("unknown flag: {flag}")),
        None => {
            println!("{}", agentd.health_report().to_json());
            Ok(())
        }
    };

    finish(result);
}

fn finish(result: Result<(), String>) {
    if let Err(error) = result {
        eprintln!("{error}");
        process::exit(2);
    }
}

fn parse_approval(value: &str) -> Result<ApprovalDecision, String> {
    match value {
        "approved" | "approve" => Ok(ApprovalDecision::Approved),
        "denied" | "deny" => Ok(ApprovalDecision::Denied),
        "timed_out" | "timeout" => Ok(ApprovalDecision::TimedOut),
        "suspended" | "suspend" => Ok(ApprovalDecision::Suspended),
        other => Err(format!("unknown approval decision: {other}")),
    }
}

fn run_interactive(agentd: &Agentd) -> Result<(), String> {
    println!("AIOS agentd TUI");
    println!("Enter intent, or empty line to exit.");
    loop {
        print!("aios> ");
        io::stdout()
            .flush()
            .map_err(|error| format!("flush failed: {error}"))?;
        let mut intent = String::new();
        io::stdin()
            .read_line(&mut intent)
            .map_err(|error| format!("read failed: {error}"))?;
        let intent = intent.trim();
        if intent.is_empty() {
            break;
        }
        let session = build_demo_session(agentd, intent, ApprovalDecision::Suspended);
        print!("{}", session.render());
    }
    Ok(())
}

fn run_audit_demo(path: &str) -> Result<(), String> {
    let journal = AuditJournal::new(path);
    journal
        .append(&AuditEvent::new(
            AuditEventType::IntentReceived,
            "run-demo",
            "step-001",
            "operator",
            "recover local service",
        ))
        .map_err(|error| error.to_string())?;
    journal
        .append(&AuditEvent::new(
            AuditEventType::EffectPrepared,
            "run-demo",
            "step-001",
            "operator",
            "prepared svc.restart password=should-not-log",
        ))
        .map_err(|error| error.to_string())?;
    println!(
        "{{\"latest_run\":\"{}\",\"unresolved_effects\":{}}}",
        journal
            .latest_run()
            .map_err(|error| error.to_string())?
            .unwrap_or_default(),
        journal
            .unresolved_effects()
            .map_err(|error| error.to_string())?
            .len()
    );
    Ok(())
}

fn run_recovery_demo(path: &str) -> Result<(), String> {
    let journal = AuditJournal::new(path);
    journal
        .append(&AuditEvent::new(
            AuditEventType::EffectPrepared,
            "run-recovery",
            "step-read",
            "operator",
            "prepared read-only svc.status",
        ))
        .map_err(|error| error.to_string())?;
    journal
        .append(&AuditEvent::new(
            AuditEventType::EffectPrepared,
            "run-recovery",
            "step-write",
            "operator",
            "prepared fs.write.diff",
        ))
        .map_err(|error| error.to_string())?;
    let report = RecoveryReconciler
        .reconcile(&journal, "run-recovery")
        .map_err(|error| error.to_string())?;
    println!("{}", report.to_json());
    println!("{}", report.render_prompt());
    Ok(())
}

fn run_policy_demo(agentd: &Agentd, path: &str) -> Result<(), String> {
    let routed = agentd
        .route_tool(&SemanticToolCall::new(
            "fs.write.diff",
            vec![("path", "/etc/nginx/nginx.conf"), ("content_hash", "abc")],
        ))
        .map_err(|error| error.reason)?;
    let request = PolicyRequest::from_routed("operator", &routed);
    let evaluator = PolicyEvaluator;
    let paused = evaluator.evaluate(&request, None);
    let token = ApprovalToken {
        actor: request.actor.clone(),
        tool: request.tool.clone(),
        resource: request.resource.clone(),
        parameter_hash: request.parameter_hash.clone(),
        expires_at: 60,
        policy_version: request.policy_version.clone(),
    };
    let allowed = evaluator.evaluate(&request, Some(&token));
    let lease = evaluator
        .acquire_lease(&request, &allowed)
        .map_err(|error| error.to_string())?;
    let denied_request = PolicyRequest {
        actor: "operator".to_string(),
        tool: "shell.exec".to_string(),
        resource: "host".to_string(),
        risk: RiskClass::Never,
        parameter_hash: stable_parameter_hash(&[("cmd".to_string(), "id".to_string())]),
        policy_version: "policy-v1".to_string(),
        now: 0,
    };
    let denied = evaluator.evaluate(&denied_request, None);

    let journal = AuditJournal::new(path);
    evaluator
        .record_decision(&journal, "run-policy", "step-write", &request, &paused)
        .map_err(|error| error.to_string())?;
    evaluator
        .record_decision(
            &journal,
            "run-policy",
            "step-denied",
            &denied_request,
            &denied,
        )
        .map_err(|error| error.to_string())?;
    let mut approval_event = AuditEvent::new(
        AuditEventType::ApprovalBound,
        "run-policy",
        "step-write",
        "operator",
        format!(
            "lease_id={} actor={} tool={} resource={} expires_at={} risk={}",
            lease.lease_id,
            lease.actor,
            lease.tool,
            lease.resource,
            lease.expires_at,
            lease.risk.as_str()
        ),
    );
    approval_event.policy_version = lease.policy_version.clone();
    approval_event.tool_version = "tool-v1".to_string();
    approval_event.parameter_hash = lease.parameter_hash.clone();
    journal
        .append(&approval_event)
        .map_err(|error| error.to_string())?;

    println!(
        "{{\"without_approval\":{},\"with_approval\":{},\"denied\":{},\"lease\":{},\"audit_path\":\"{}\"}}",
        paused.to_json(),
        allowed.to_json(),
        denied.to_json(),
        lease.to_json(),
        agentd::api::escape_json(path)
    );
    Ok(())
}

fn run_sandbox_demo(agentd: &Agentd, path: &str) -> Result<(), String> {
    let routed = agentd
        .route_tool(&SemanticToolCall::new("fs.read", vec![("path", "/var/log/agentd.log")]))
        .map_err(|error| error.reason)?;
    let request = PolicyRequest::from_routed("operator", &routed);
    let evaluator = PolicyEvaluator;
    let decision = evaluator.evaluate(&request, None);
    let lease = evaluator
        .acquire_lease(&request, &decision)
        .map_err(|error| error.to_string())?;
    let profile = SandboxCompiler
        .compile(&lease)
        .map_err(|error| error.reason())?;
    let executor = SandboxExecutor;
    let read = executor.evaluate(
        &profile,
        SandboxOperation::ReadDiagnostic {
            label: "fs.read /var/log/agentd.log".to_string(),
        },
    );
    let write_denied = executor.evaluate(
        &profile,
        SandboxOperation::WritePersistentPath {
            path: "/etc/passwd".to_string(),
        },
    );
    let fork_denied = executor.evaluate(&profile, SandboxOperation::SpawnProcesses { count: 1024 });
    let syscall_denied = executor.evaluate(
        &profile,
        SandboxOperation::Syscall {
            name: "mount".to_string(),
        },
    );

    let journal = AuditJournal::new(path);
    executor
        .record_report(&journal, "run-sandbox", "step-write", &write_denied)
        .map_err(|error| error.to_string())?;
    executor
        .record_report(&journal, "run-sandbox", "step-fork", &fork_denied)
        .map_err(|error| error.to_string())?;
    executor
        .record_report(&journal, "run-sandbox", "step-syscall", &syscall_denied)
        .map_err(|error| error.to_string())?;

    println!(
        "{{\"profile\":{},\"read\":{},\"write_denied\":{},\"fork_denied\":{},\"syscall_denied\":{},\"audit_path\":\"{}\"}}",
        profile.to_json(),
        read.to_json(),
        write_denied.to_json(),
        fork_denied.to_json(),
        syscall_denied.to_json(),
        agentd::api::escape_json(path)
    );
    Ok(())
}

fn run_write_diff_demo(agentd: &Agentd, root: PathBuf) -> Result<(), String> {
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let target = root.join("target.conf");
    fs::write(&target, "port=80\n").map_err(|error| error.to_string())?;
    let base_hash = content_hash("port=80\n");
    let proposed_hash = content_hash("port=8080\n");

    let target_param = target.display().to_string();
    let routed = agentd
        .route_tool(&SemanticToolCall::new(
            "fs.write.diff",
            vec![
                ("path", target_param.as_str()),
                ("content_hash", proposed_hash.as_str()),
                ("base_hash", base_hash.as_str()),
            ],
        ))
        .map_err(|error| error.reason)?;
    let request = PolicyRequest::from_routed("operator", &routed);
    let evaluator = PolicyEvaluator;
    let token = ApprovalToken {
        actor: request.actor.clone(),
        tool: request.tool.clone(),
        resource: request.resource.clone(),
        parameter_hash: request.parameter_hash.clone(),
        expires_at: 60,
        policy_version: request.policy_version.clone(),
    };
    let decision = evaluator.evaluate(&request, Some(&token));
    let lease = evaluator
        .acquire_lease(&request, &decision)
        .map_err(|error| error.to_string())?;
    let executor = WriteDiffExecutor::new(root.join("shadow"));
    let write_request = WriteRequest {
        run_id: "run-write-diff".to_string(),
        step_id: "step-write".to_string(),
        actor: "operator".to_string(),
        target_path: target.clone(),
        proposed_content: "port=8080\n".to_string(),
        base_hash,
    };
    let mut prepared = executor
        .prepare(&lease, write_request)
        .map_err(|error| error.reason())?;
    let untouched_before_commit = fs::read_to_string(&target).map_err(|error| error.to_string())?;
    let journal = AuditJournal::new(root.join("audit.jsonl"));
    let commit = executor
        .commit(&journal, &mut prepared)
        .map_err(|error| error.reason())?;
    let after_commit = fs::read_to_string(&target).map_err(|error| error.to_string())?;
    let rollback = executor
        .rollback(
            &journal,
            &prepared.handle,
            "run-write-diff",
            "step-write",
            "operator",
        )
        .map_err(|error| error.reason())?;
    let after_rollback = fs::read_to_string(&target).map_err(|error| error.to_string())?;
    println!(
        "{{\"preview\":{},\"handle\":{},\"untouched_before_commit\":\"{}\",\"commit\":{},\"after_commit\":\"{}\",\"rollback\":{},\"after_rollback\":\"{}\",\"audit_path\":\"{}\"}}",
        prepared.preview.to_json(),
        prepared.handle.to_json(),
        agentd::api::escape_json(&untouched_before_commit),
        commit.to_json(),
        agentd::api::escape_json(&after_commit),
        rollback.to_json(),
        agentd::api::escape_json(&after_rollback),
        agentd::api::escape_json(&root.join("audit.jsonl").display().to_string())
    );
    Ok(())
}

fn run_service_recovery_demo(path: &str, approval: RestartApproval) -> Result<(), String> {
    let journal = AuditJournal::new(path);
    let report = ServiceRecoveryWorkflow.run(&journal, ServiceFixture::degraded_nginx(), approval)?;
    println!("{}", report.to_json());
    Ok(())
}

fn run_audit_show(path: &str, run_id: Option<&str>) -> Result<(), String> {
    let journal = AuditJournal::new(path);
    let latest_run;
    let run_id = match run_id {
        Some("latest") | None => {
            latest_run = journal
                .latest_run()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "audit journal has no runs".to_string())?;
            latest_run.as_str()
        }
        Some(run_id) => run_id,
    };
    let lines = journal
        .run_timeline(run_id)
        .map_err(|error| error.to_string())?;
    println!("[{}]", lines.join(","));
    Ok(())
}

fn parse_params(args: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut params = Vec::new();
    for arg in args {
        let Some((key, value)) = arg.split_once('=') else {
            return Err(format!("parameter must be key=value: {arg}"));
        };
        params.push((key.to_string(), value.to_string()));
    }
    Ok(params)
}
