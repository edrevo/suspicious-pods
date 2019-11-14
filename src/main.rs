use clap::{Arg, App};
use suspicious_pods_lib::{
  get_suspicious_pods,
  Result,
  SuspiciousPodReason
};

fn main() -> Result<()> {
  let matches = App::new("suspicious-pods")
    .version("0.4")
    .about("Prints a list of k8s pods that might not be working correctly")
    .arg(Arg::with_name("namespace")
      .required(true)
      .default_value("default")
      .help("The namespace you want to scan")
      .takes_value(true))
    .arg(Arg::with_name("format")
      .long("format")
      .short("f")
      .required(true)
      .default_value("text")
      .help("The output format. Valid values are: text, markdown")
      .takes_value(true))
    .get_matches();
  let namespace = matches.value_of("namespace").unwrap();
  let format = matches.value_of("format").unwrap();
  let suspicious_pods = get_suspicious_pods(namespace)?;
  match format {
    "text" => {
      for pod in suspicious_pods {
        match pod.reason {
          SuspiciousPodReason::StuckOnInitContainer(init) => {
            println!("{: <50} Stuck on init container: {}", pod.name, init);
          },
          SuspiciousPodReason::SuspiciousContainers(containers) => {
            for container in containers {
              let coord = format!("{}/{}", pod.name, container.name);
              println!("{: <60}\t{}", coord, container.reason);
            }
          }
        }
      }
    },
    "markdown" => {
      println!("#### {}", namespace);
      println!();
      for pod in suspicious_pods {
        println!("**{}**", pod.name);
        println!();
        match pod.reason {
          SuspiciousPodReason::StuckOnInitContainer(init) => {
            println!("- Stuck on init container: {}", init);
          },
          SuspiciousPodReason::SuspiciousContainers(containers) => {
            for container in containers {
              println!("- Container: {} `{}`", container.name, container.reason);
            }
          }
        }
        println!();
      }
    },
    _ => println!("Invalid format {}", format)
  };
  Ok(())
}

