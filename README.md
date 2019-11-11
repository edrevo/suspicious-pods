# Suspicious pods

![crates.io](https://img.shields.io/crates/v/suspicious-pods.svg)

Suspicious pods is a very simple tool, which does a very simple task: print a list of pods in your Kubernetes cluster that might not be working correctly, along with a reason on why that pod is considered suspicious.

Example:

```bash
$ suspicious-pods -- help
suspicious-pods 0.3
Prints a list of k8s pods that might not be working correctly

USAGE:
    suspicious-pods.exe <namespace> --format <format>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f, --format <format>    The output format. Valid values are: text, markdown [default: text]

ARGS:
    <namespace>    The namespace you want to scan [default: default]
    
$ suspicious-pods

fluentd-aggregator-0
  Container: fluentd-aggregator         Restarted { count: 6, exit_code: 1, reason: Some("Error") }
fluentd-aggregator-2
  Container: fluentd-aggregator         Restarted { count: 6, exit_code: 1, reason: Some("Error") }
fluentd-aggregator-3
  Container: fluentd-aggregator         Restarted { count: 1, exit_code: 1, reason: Some("Error") }
fluentd-dgjm8
  Container: fluentd                    ContainerWaiting(Some("PodInitializing"))
jaeger-es-index-cleaner-1572220860-jd7b4
  Container: jaeger-es-index-cleaner    ContainerWaiting(Some("ImagePullBackOff"))
jaeger-es-index-cleaner-1572307260-5w5kn
  Container: jaeger-es-index-cleaner    ContainerWaiting(Some("ImagePullBackOff"))
jaeger-operator-5545d554cb-mf5zt
  Container: jaeger-operator            Restarted { count: 3, exit_code: 137, reason: Some("OOMKilled") }
kube-graffiti-5dc8765dc5-mxc2g
  Container: kube-graffiti              Restarted { count: 2, exit_code: 1, reason: Some("Error") }
prometheus-0
  Container: prometheus                 Restarted { count: 1, exit_code: 1, reason: Some("Error") }
prometheus-1
  Container: prometheus                 Restarted { count: 1, exit_code: 1, reason: Some("Error") }
thanos-store-gateway-0
  Container: thanos-store-gateway       Restarted { count: 1, exit_code: 137, reason: Some("OOMKilled") }
```

This is useful in big deployments, when you have a large number of pods and you just want to get a quick glimpse of what might be failing in your cluster.

## Installation

### Option 1: Precompiled binaries

Head to the releases and download your binary. There are binaries for Windows and Linux. On Windows, you need to have OpenSSL installed on your machine through [vcpkg](https://github.com/Microsoft/vcpkg)

### Option 2: Cargo

Install [rustup](https://rustup.rs/) and run `cargo install suspicious-pods`. If you are on Windows, you need to have OpenSSL installed on your machine through [vcpkg](https://github.com/Microsoft/vcpkg) and set the environment variable `VCPKGRS_DYNAMIC=1`.


## Feedback

Feedback and contributions are welcome! Please open an issue or a PR.
