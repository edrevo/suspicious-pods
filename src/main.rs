use ansi_term::Style;
use clap::{App, Arg};
use itertools::Itertools;
use suspicious_pods_lib::*;

fn display_pods<T>(namespace: Option<&str>, suspicious_pods: T)
where
    T: Iterator<Item = SuspiciousPod>,
{
    if let Some(ns) = namespace {
        let namespace_title = format!("Namespace {}", ns);
        println!("{}", Style::new().bold().underline().paint(namespace_title));
    }
    for pod in suspicious_pods {
        match pod.reason {
            SuspiciousPodReason::Pending => {
                println!("{: <60} Pending", pod.name);
            }
            SuspiciousPodReason::StuckOnInitContainer(init) => {
                println!("{: <60} Stuck on init container: {}", pod.name, init);
            }
            SuspiciousPodReason::SuspiciousContainers(containers) => {
                for container in containers {
                    let coord = format!("{}/{}", pod.name, container.name);
                    println!("{: <60} {}", coord, container.reason);
                }
            }
        }
    }
    println!();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let matches = App::new("suspicious-pods")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Prints a list of k8s pods that might not be working correctly")
        .arg(
            Arg::with_name("namespace")
                .required(true)
                .default_value("default")
                .help("The namespace you want to scan")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("all-namespaces")
                .long("--all-namespaces")
                .takes_value(false)
                .help("Set this flag to scan all namespaces in the cluster"),
        )
        .get_matches();
    let namespace = matches.value_of("namespace").unwrap();
    if matches.is_present("all-namespaces") {
        let groups = get_all_suspicious_pods()
            .await?
            .group_by(|p| p.namespace.to_string());
        for (namespace, group) in &groups {
            display_pods(Some(&namespace), group);
        }
    } else {
        display_pods(None, get_suspicious_pods(namespace).await?);
    };
    Ok(())
}
