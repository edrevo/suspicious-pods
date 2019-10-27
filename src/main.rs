use clap::{Arg, App};
use kube::{
  api::{Api, Object},
  client::APIClient,
  config,
  Error
};
use k8s_openapi::api::core::v1::{ContainerStatus, PodSpec, PodStatus};
use std::result::Result;

#[derive(Debug)]
enum SuspiciousContainerReason<'a> {
  ContainerWaiting(Option<&'a str>),
  Restarted { count: i32, exit_code: i32, reason: &'a Option<String> },
  TerminatedWithError(i32)
}

#[derive(Debug)]
struct SuspiciousContainer<'a> {
  name: &'a str,
  reason: SuspiciousContainerReason<'a>
}

#[derive(Debug)]
struct SuspiciousPod<'a> {
  name: &'a str,
  suspicious_containers: Vec<SuspiciousContainer<'a>>
}

fn is_suspicious(p: &Object<PodSpec, PodStatus>) -> Option<SuspiciousPod> {
  let pod_name = &p.metadata.name;
  let status = p.status.as_ref()
    .expect(format!("Cannot get status for pod {}", pod_name).as_str());
  let statuses: &Vec<ContainerStatus> = status.container_statuses.as_ref()
    .expect(format!("Cannot get container statuses for pod {}", pod_name).as_str());;
  let suspicious_containers: Vec<_> = statuses.iter().filter_map(|status: &ContainerStatus| {
    let container_name = &status.name;
    let state = status.state.as_ref()
      .expect(format!("Cannot get state for container {} in pod {}", container_name, pod_name).as_str());
    let reason = if status.restart_count > 0 {
      let last_state = status.last_state.as_ref()
        .expect(format!("Cannot get last state for container {} in pod {}", container_name, pod_name).as_str())
        .terminated
        .as_ref()
        .unwrap();
      Some(SuspiciousContainerReason::Restarted {
        count: status.restart_count,
        exit_code: last_state.exit_code,
        reason: &last_state.reason
      })
    } else if let Some(waiting_state) = &state.waiting {
      let msg: Option<&str> = waiting_state.reason.as_ref().or(waiting_state.message.as_ref()).map(String::as_str);
      Some(SuspiciousContainerReason::ContainerWaiting(msg))
    } else if state.terminated.is_some() && state.terminated.as_ref().unwrap().exit_code != 0 {
      Some(SuspiciousContainerReason::TerminatedWithError(state.terminated.as_ref().unwrap().exit_code))
    } else {
      None
    };
    reason.map(|reason| SuspiciousContainer {
      name: container_name,
      reason
    })
  }).collect();

  if suspicious_containers.is_empty() {
    None
  } else {
    Some(SuspiciousPod {
      name: pod_name,
      suspicious_containers
    })
  }
}

fn main() -> Result<(), Error> {
  let matches = App::new("suspicious-pods")
    .version("0.1")
    .about("Prints a list of k8s pods that might not be working correctly")
    .arg(Arg::with_name("namespace")
      .required(true)
      .default_value("default")
      .help("The namespace you want to scan")
      .takes_value(true))
    .get_matches();
  let namespace = matches.value_of("namespace").unwrap();
  let config = config::load_kube_config().expect("failed to load kubeconfig");
  let client = APIClient::new(config);
  let pods = Api::v1Pod(client).within(namespace).list(&Default::default())?;
  let suspicious_pods: Vec<_> = pods.items.iter()
    .filter_map(is_suspicious)
    .collect();
  for pod in suspicious_pods {
    println!("{:?}", pod.name);
    for container in pod.suspicious_containers {
      println!("  {:?}", container);
    }
  }
  Ok(())
}

