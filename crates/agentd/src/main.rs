use std::env;
use std::io::{self, Write};
use std::process;

use agentd::{
    api::SemanticToolCall,
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
