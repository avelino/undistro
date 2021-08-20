# 3 - Installing UnDistro

UnDistro requires an existing Kubernetes cluster accessible via kubectl. During the installation process
the Kubernetes cluster will be transformed into a [management cluster](./docs#Management-Cluster) by installing the UnDistro [provider components](./docs#Provider-Components), so it
is recommended to keep it separated from any application workload.

It is a common practice to create a temporary, local bootstrap cluster which is then used to provision
a target [management cluster](./docs#management-cluster) on the selected [infrastructure provider](./docs#infrastructure-provider).

After [prepare the environment](./docs#prepare-environment) choose one of the options below:

- [**Existing Cluster**](./docs#existing-cluster)
- [**Kind**](./docs#kind)

## Prepare environment

- Install and setup [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) in your local environment
- Install and setup [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) and [Docker](https://www.docker.com/get-started) **(required just for kind installation method)**
- Install and setup [aws-iam-authenticator](https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html) in your local environment **(required just for AWS provider)**
- Install [NSS Tools](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools) in your OS using your favorite package manager (rpm/deb/apk)
  > :warning: **If the installation is from rpm, deb, apk or brew package managers it will also install nss tools for you**: Be very careful here!

## Existing Cluster

For production use-cases a "real" Kubernetes cluster should be used with appropriate backup and DR policies and procedures in place.

```bash
export KUBECONFIG={...}
```

## Kind

[Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) is not designed for production use.

**Minimum [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) supported version**: v0.9.0

Can be used for creating a local Kubernetes cluster for development environments or for the creation of local bootstrap cluster which is then used to provision
a target
[management cluster](./docs#Management-Cluster) on the selected [infrastructure provider](./docs#Infrastructure-Provider).

## Download UnDistro CLI

The UnDistro CLI tool handles the lifecycle of an UnDistro management cluster.

Download the latest version from the releases page: https://github.com/getupio-undistro/undistro/releases or use Homebrew to install.

```bash
brew install getupio-undistro/tap/undistro
```

## Create the configuration file

The configuration changes according to provider we want to install. Know more in [configuration page](./docs#configuration)

##  Setup Kind

If you decide to use a Kind cluster, you can use UnDistro to setup it for you.

```bash
undistro setup kind
```

## Initialize the management cluster

Now that we have got UnDistro CLI installed and all the prerequisites are in place, let's transform the Kubernetes cluster
into a management cluster by using **undistro install**.

```bash
undistro --config undistro-config.yaml install
```

## Upgrade a provider into management cluster

```bash
undistro upgrade {provider name}
```

&nbsp;

&nbsp;