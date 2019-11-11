use clap::{Arg, App};
use suspicious_pods_lib::{get_suspicious_pods, Result};

fn main() -> Result<()> {
  let matches = App::new("suspicious-pods")
    .version("0.3")
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
        println!("{}", pod.name);
        for container in pod.suspicious_containers {
          println!("  Container: {: <25}\t{:?}", container.name, container.reason);
        }
      }
    },
    "markdown" => {
      println!("#### {}", namespace);
      println!();
      for pod in suspicious_pods {
        println!("**{}**", pod.name);
        println!();
        for container in pod.suspicious_containers {
          println!("- Container: {:} `{:?}`", container.name, container.reason);
          println!();
        }
      }
    },
    _ => println!("Invalid format {}", format)
  };
  Ok(())
}

