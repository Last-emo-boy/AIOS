use std::env;
use std::io::{self, Write};
use std::process;

use agentd::{
    api::SemanticToolCall,
    audit::{AuditEvent, AuditEventType, AuditJournal},
    lifecycle::{Agentd, LifecycleConfig},
    tui::{build_demo_session, ApprovalDecision},
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
