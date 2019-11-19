use failure::Error;
use kube::{
  api::{Api, Object},
  client::APIClient,
  config
};
use k8s_openapi::api::core::v1::{ContainerStatus, PodSpec, PodStatus};
use failure::_core::fmt::Formatter;

pub enum SuspiciousContainerReason {
  ContainerWaiting(Option<String>),
  NotReady,
  Restarted { count: i32, exit_code: Option<i32>, reason: Option<String> },
  TerminatedWithError(i32)
}

impl std::fmt::Display for SuspiciousContainerReason {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      SuspiciousContainerReason::ContainerWaiting(reason) => {
        write!(f, "Waiting")?;
        if let Some(r) = reason {
          write!(f, ": {}", r)?;
        }
      },
      SuspiciousContainerReason::NotReady => {
        write!(f, "Not Ready")?;
      },
      SuspiciousContainerReason::Restarted { count, exit_code, reason} => {
        if *count == 1 {
          write!(f, "Restarted {} time", count)?;
        } else {
          write!(f, "Restarted {} times", count)?;
        }
        if let Some(e) = exit_code {
          write!(f, ". Last exit code: {}", e)?;
        }
        if let Some(r) = reason {
          write!(f, ". ({})", r)?;
        }
      },
      SuspiciousContainerReason::TerminatedWithError(exit_code) => {
        write!(f, "Terminated with error. Exit code {}.", exit_code)?;
      }
    }
    Ok(())
  }
}

pub struct SuspiciousContainer {
  pub name: String,
  pub reason: SuspiciousContainerReason
}

pub enum SuspiciousPodReason {
  Pending,
  StuckOnInitContainer(String),
  SuspiciousContainers(Vec<SuspiciousContainer>)
}

pub struct SuspiciousPod {
  pub name: String,
  pub reason: SuspiciousPodReason
}

pub type Result<T> = std::result::Result<T, Error>;

fn is_suspicious_container(pod_name: &str, status: ContainerStatus) -> Option<SuspiciousContainer> {
  let container_name = status.name;
  let state = status.state
    .expect(format!("Cannot get state for container {} in pod {}", container_name, pod_name).as_str());
  let reason = if status.restart_count > 0 {
    let last_state = status.last_state
      .expect(format!("Cannot get last state for container {} in pod {}", container_name, pod_name).as_str())
      .terminated;
    Some(SuspiciousContainerReason::Restarted {
      count: status.restart_count,
      exit_code: last_state.as_ref().map(|s| s.exit_code),
      reason: last_state.and_then(|s| s.reason)
    })
  } else if let Some(waiting_state) = state.waiting {
    let msg: Option<String> = waiting_state.reason.or(waiting_state.message);
    Some(SuspiciousContainerReason::ContainerWaiting(msg))
  } else if state.terminated.is_some() && state.terminated.as_ref().unwrap().exit_code != 0 {
    Some(SuspiciousContainerReason::TerminatedWithError(state.terminated.unwrap().exit_code))
  } else if !status.ready {
    Some(SuspiciousContainerReason::NotReady)
  } else {
    None
  };
  reason.map(|reason| SuspiciousContainer {
    name: container_name,
    reason
  })
}

fn is_suspicious_pod(p: Object<PodSpec, PodStatus>) -> Option<SuspiciousPod> {
  let pod_name = p.metadata.name;
  let status = p.status
    .expect(format!("Cannot get status for pod {}", pod_name).as_str());
  if let Some(init_containers) = status.init_container_statuses {
    if let Some(stuck_init) = init_containers.into_iter().find(|c| !c.ready) {
      return Some(SuspiciousPod {
        name: pod_name,
        reason: SuspiciousPodReason::StuckOnInitContainer(stuck_init.name)
      })
    }
  }
  if let Some(statuses) = status.container_statuses {
    let suspicious_containers: Vec<_> = statuses
      .into_iter()
      .filter_map(|c| is_suspicious_container(&pod_name, c))
      .collect();

    if suspicious_containers.is_empty() {
      None
    } else {
      Some(SuspiciousPod {
        name: pod_name,
        reason: SuspiciousPodReason::SuspiciousContainers(suspicious_containers)
      })
    }
  } else {
    Some(SuspiciousPod {
        name: pod_name,
        reason: SuspiciousPodReason::Pending
      })
  }
}

pub fn get_suspicious_pods(namespace: &str) -> Result<Vec<SuspiciousPod>> {
  let config = config::load_kube_config()?;
  let client = APIClient::new(config);
  let pods = Api::v1Pod(client).within(namespace).list(&Default::default())?;
  Ok(pods.items.into_iter()
    .filter_map(is_suspicious_pod)
    .collect())
}
