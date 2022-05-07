# Suspicious pods

![crates.io](https://img.shields.io/crates/v/suspicious-pods.svg)

Suspicious pods is a very simple tool, which does a very simple task: print a list of pods in your Kubernetes cluster that might not be working correctly, along with a reason on why that pod is considered suspicious.

Example:

```
$ suspicious-pods --help
suspicious-pods 1.2.0
Prints a list of k8s pods that might not be working correctly

USAGE:
    suspicious-pods.exe [FLAGS] <namespace>

FLAGS:
        --all-namespaces    Set this flag to scan all namespaces in the cluster
    -h, --help              Prints help information
    -V, --version           Prints version information

ARGS:
    <namespace>    The namespace you want to scan [default: default]
    
$ suspicious-pods

fluentd-aggregator-0/fluentd-aggregator                         Restarted 6 times. Last exit code: 1. (Error)
fluentd-dgjm8/fluentd                                           Waiting: PodInitializing
jaeger-es-index-cleaner-120860-jd7b4/jaeger-es-index-cleaner    Waiting: ImagePullBackOff
jaeger-operator-5545d554cb-mf5zt/jaeger-operator                Restarted 3 times. Last exit code: 137. (OOMKilled)
thanos-store-gateway-0                                          Stuck on init container: wait-for-prometheus
```

This is useful in big deployments, when you have a large number of pods and you just want to get a quick glimpse of what might be failing in your cluster.

## Installation

### Option 1: Precompiled binaries

Head to the [release page](https://github.com/edrevo/suspicious-pods/releases) and download your binary. There are binaries for Windows, Linux and MacOS. On Windows, you need to have OpenSSL installed on your machine. You can install it through [vcpkg](https://github.com/Microsoft/vcpkg)

### Option 2: Cargo

Install [rustup](https://rustup.rs/) and run `cargo install suspicious-pods`. If you are on Windows, you need to have OpenSSL installed on your machine through [vcpkg](https://github.com/Microsoft/vcpkg) and set the environment variable `VCPKGRS_DYNAMIC=1`.


## Feedback

Feedback and contributions are welcome! Please open an issue or a PR.
