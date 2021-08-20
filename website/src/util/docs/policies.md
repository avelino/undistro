
# 8 - Policies

The purpose of policies in UnDistro is simple: They define settings that should be applied across the cluster. But at a high level, UnDistro policies serve to create and enforce effective and efficient governance rules.

## Default policies

By default, UnDistro applies the following governance policies:

| Name                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| disallow-add-capabilities  | Capabilities permit privileged actions without giving full root access. Adding capabilities beyond the default set must not be allowed                                                                                                                                                                                                                                                                                                                                                              |
| disallow-default-namespace | Kubernetes namespaces are an optional feature that provide a way to segment and isolate cluster resources across multiple applications and users. As a best practice, workloads should be isolated with namespaces. Namespaces should be required and the default (empty) namespace should not be used.                                                                                                                                                                                             |
| deny-delete-kyverno        | Prevent kyverno resources removal                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| disallow-host-namespace    | Host namespaces (Process ID namespace, Inter-Process Communication namespace, and network namespace) allow access to shared information and can be used to elevate privileges. Pods should not be allowed access to host namespaces.                                                                                                                                                                                                                                                                |
| disallow-host-path         | HostPath volumes let pods use host directories and volumes in containers Using host resources can be used to access shared data or escalate privileges and should not be allowed.                                                                                                                                                                                                                                                                                                                   |
| disallow-host-port         | Access to host ports allows potential snooping of network traffic and should not be allowed, or at minimum restricted to a known list.                                                                                                                                                                                                                                                                                                                                                              |
| disallow-latest-tag        | Prevents the use of the latest image.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| require-requests-limits    | As application workloads share cluster resources, it is important to limit resources requested and consumed by each pod. It is recommended to require 'resources.requests' and 'resources.limits.memory' per pod. If a namespace level request or limit is specified, defaults will automatically be applied to each pod based on the 'LimitRange' configuration.                                                                                                                                   |
| traffic-deny               | By default, Kubernetes allows communications across all pods within a cluster. Network policies and, a CNI that supports network policies, must be used to restrict communications. UnDistro uses Calico CNI. A default NetworkPolicy should be configured for each namespace to default deny all ingress and egress traffic to the pods in the namespace. Application teams can then configure additional NetworkPolicy resources to allow desired traffic to application pods from select sources |

## Network policy

UnDistro deny all trafic between namespaces by default, to allow ingress and egress trafic add the labels below into your pods spec:

- **Ingress**

```yaml
network.undistro.io/ingress: allow
```

- **Egress**

```yaml
network.undistro.io/egress: allow
```

## Default policies management

Applied Policies can be disabled using the following configuration:

```yaml
apiVersion: app.undistro.io/v1alpha1
kind: DefaultPolicies
metadata:
  name: defaultpolicies-sample
  namespace: yourclusternamespace
spec:
  clusterName: yourclustername
  excludePolicies:
    - policy1
    - policy2
```

## Applying customized policies

You can use customized policies rules.
UnDistro policies are provided by Kyverno, please refer do Kyverno documentation to write custom policies [here](https://kyverno.io/docs/writing-policies/).

```bash
undistro apply -f custompoliciesfile.yaml
```

&nbsp;

&nbsp;