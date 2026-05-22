use std::env;
use std::process;

use agentd::{
    api::SemanticToolCall,
    lifecycle::{Agentd, LifecycleConfig},
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

    if let Err(error) = result {
        eprintln!("{error}");
        process::exit(2);
    }
}
