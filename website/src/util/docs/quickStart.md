# 2 - Quick Start

Follow these steps to easily create your first cluster with UnDistro.

Before you start, make sure the following prerequisites are installed:

- Install and setup [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) in your local environment.
- Install and setup [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) and [Docker](https://www.docker.com/get-started). **(required just for kind installation method)**
- Install and setup [aws-iam-authenticator](https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html) in your local environment. **(required just for AWS provider)**
- Install [NSS Tools](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools) in your OS using your favorite package manager (rpm/deb/apk)
  > :warning: **If the installation is from rpm, deb, apk or brew package managers it will also install nss tools for you**: Be very careful here!
- Download [UnDistro CLI](https://github.com/getupio-undistro/undistro/releases) or use Homebrew to install.

```bash
brew install getupio-undistro/tap/undistro
```

**Great tips!**

- The cluster name cannot be changed after it is created, choose it right, choose it well!
- The namespace cannot be changed after the cluster is created, choose it right, choose it well!
- Get in advance the keys from the provider you will need to use, be prepared!

![Image of quick start steps](https://raw.githubusercontent.com/getupio-undistro/undistro/main/website/src/assets/images/quick-start.jpg)

## Step 1

To get started we will create a Kind cluster, open your terminal and type:

```bash
kind create cluster
```

## Step 2

Now let's create the configuration file for UnDistro containing the AWS credentials. These credentials must have admin access rights:

```yaml
undistro-aws:
  enabled: true
  credentials:
    accessKeyID: put your key here
    secretAccessKey: put your key here
    sessionToken: put your key here # if you use 2FA
    region: put your key here # default region us-east-1
```

## Step 3

We will now install UnDistro on the Kind cluster we just created:

```console
undistro --config <your configuration file path created in step 2> install
```

## Step 4

Let's generate the UnDistro recommended cluster configuration for the AWS provider. Here we have two possible scenarios:

- First scenario - using EC2 \* you will need an AWS pre configured ssh-key

* https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair

```bash
undistro create cluster yourclustername --namespace yourclusternamespace --infra aws --flavor ec2 --ssh-key-name yoursshkeyname --generate-file
```

- Second scenario - using EKS

```bash
undistro create cluster yourclustername --namespace yourclusternamespace --infra aws --flavor eks --generate-file
```

both of the above command lines will generate a cluster configuration file called `yourclustername.yaml`

## Step 5

Let's apply the configuration file generated in step 4:

```bash
undistro apply -f yourclustername.yaml
```

## Step 6

During the installation you can check the progress with command below:

```bash
undistro show-progress yourclustername -n yourclusternamespace
```

## Step 7

The cluster creation will take some time to finish, you can check the installation status using the following command line:

```bash
undistro get clusters yourclustername -n yourclusternamespace
```

## Step 8

Once you have finished the installation retrieve the kubeconfig to access the created cluster:

```bash
undistro get kubeconfig yourclustername -n yourclusternamespace
```

- _For more information about UnDistro, please refer to the next topics of this document._

## Step 9

To delete all resources created by undistro, run the command line below

```bash
undistro delete -f yourclustername.yaml
```