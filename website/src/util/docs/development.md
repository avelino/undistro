# 11 - Development
## How to setup the development environment

The first step in getting involved with Undistro is to download the source code, and since the development is carried out by means of the Git version control system, it can be used to clone the [repository](https://github.com/getupio-undistro/undistro). If you don't already have Git installed, it can be found in most package managers as well as in the official downloads [page](https://git-scm.com/downloads). Furthermore, a Github account will also be required for sending changes back, so be sure to have one.

Both backend and frontend software lies on the same repository. The second is mostly composed by the _UI_ folder, while the first is by the _apis_, _controllers_, _pkg_,_cmd_ and _tilt\_modules_ folders, as well as by many files in the root directory. Such folders will be discussed with more details later on.

<br/>
 

### Backend

Undistro's backed is mostly written in the Go programming language. Go is a concise, statically typed, compiled language with a powerful concurrency model, also being the language in which Kubernetes is written. Most software repositories have a package for Go, but any case, it can also be obtained in [this page](https://golang.org/dl/).

Another crucial piece of software to write code for Undistro is Helm, which is a package manager for Kubernetes, providing a unified way to share, track and upgrade cluster setups. Helm is distributed as a single statically linked binary, which can be obtained [here](https://helm.sh/docs/intro/install/).

Next, a local Kubernetes cluster must be created. Any Kubernetes distribution should suffice, but KinD and Minikube have been the ones where most testing has occurred. KinD stands for "Kubernetes in Docker", being a tool used to run Kubernetes clusters locally through Docker containers. Head over to its [website](https://kind.sigs.k8s.io/) for installation instructions. Minikube is an advanced tool used to run local Kubernetes clusters which supports multiple runtimes such as Virtual Machines, Container engines or the host OS. It also supports LoadBalancers and plugins for a diverse set of purposes. Check out Minikube's [documentation](https://minikube.sigs.k8s.io/docs/start/) for installation instructions.

KinD has the advantage of speed, being very quick to create and execute clusters. On the other hand, Minikube wins at extensibility, its multiple runtime options permit a finer-grained setup, and the plugins greatly simplify its configuration. Choose one of them to proceed with the setup.

In a similar way, Docker is another one of the requirements to set up UnDistro locally. Docker is a container runtime used to package programs and their dependencies in an image, making it very portable and isolating its execution from the host operating system. Install it with your package manager or through Docker's get started [page](https://www.docker.com/get-started).

Undistro's source code provides some automated methods of setting up your cluster for development, as well as a local Docker registry used to push and pull Undistro images. The most simple method works through _make targets_, which are laid out as follows.

<br/>

- _cli_ : Used to compile the terminal installer, outputting a binary called _undistro_;

- _setup\_kind_ : This target will create a KinD cluster and a Docker registry on the host OS, configuring the cluster to use it;

- _setup\_minikube_ : This target will create and configure a Minikube cluster with an internal Docker registry;

- _cli-install\_kind_ : Aside from invoking the targets _cli_ and _setup\_kind_, it installs Undistro in a KinD cluster;

- _cli-install\_minikube_ : Similarly to the previous rule it compiles a _cli_ binary, but calling the _setup\_minikube_ target instead, and then installing Undistro in the created Minikube cluster;

- _cli-install\_minikube_: Similarly to the previous rule it compiles a _cli_ binary, but calling the _setup\_minikube_ target instead, and then installing Undistro in the created Minikube cluster;
<br/>

Among the configurations applied on the cluster is the placement of a node label through Kubelet, which makes the _nginx-controller_ target it by means of a node selector. This label is named "_ingress-ready=true_". In similar way, port-mapping also takes place in such configurations, opening the ports 80, 443 and 6443 in the Kubernetes cluster, further mapping them to the same ports on the host by means of the Docker engine. The first two ports are used in the frontend and will be discussed in the next section. The last port is used for Undistro's identity management.

In the case of a KinD setup, an extra configuration is applied to the _containerd_ runtime, which directs the cluster towards the local registry. This is done through the _registry.mirrors_ section of the _io.containerd.grpc.v1.cri_ plugin.

The make targets can be customized by means of environment variables. Following is a list of them.

<br/>

- _KIND\_CLUSTER\_NAME_ : Defines the name for the cluster created when using KinD;
- _REG\_PORT_ : The port used to connect with the registry, defaulting to 5000 if not set;
- _REG\_HOST_ : The registry host, having the value of "localhost" if not set;
- _REG\_ADDR_ : The registry address, defaulting to a composition of the previous two variables as "_$REG\_HOST:$REG\_PORT_" when not set;
- _MINIK\_IP_ : Sets the IP address of the Minikube runtime, having no defaults;
- _UND\_IMG_\_TAG : The tag used for the Undistro's images, defaulting to "latest" if not specified;
- _UND\_CONF_ : Defines the name of the Undistro configuration file, which defaults to _undistro.yaml_ when not set;
<br/>

**Warning!** When using Minikube, the variable _MINIK_IP_ must be set, otherwise Undistro's images will not be pushed to Minikube's internal registry. It also must be the same as the _REG\_HOST_ variable. To discover the IP address of your Minikube runtime, run the command _minikube start && minikube ip_, then stop and delete the created cluster.


Following are some usage examples of the _make_ rules. The first one creates a KinD cluster and a local registry, publishing Undistro's images with the tag _feature\_test and then installing it with the configuration file _my\_conf.yaml_.

~~~sh
$ make cli-kind_install UND_IMG_TAG=feature_test UND_CONF=my_conf.yaml
~~~

The second one sets up a Minikube cluster and an internal registry with the address 192.168.39.2, listening at the port 5000 by default, further installing Undistro into it.

~~~sh
$ make cli-minikube_install MINIK_IP=192.168.39.2 REG_HOST=192.168.39.2
~~~

The third example prepares a KinD cluster and a registry locally, listening in the URL _http://localhost:3000_.

~~~sh
$ make setup_kind REG_PORT=3000
~~~

The fourth example, creates a Minikube cluster and configure its internal registry to listen in the address 192.168.39.2 at the port 4999.

~~~sh
$ make setup_minikube MINIK_IP=192.168.39.2 REG_ADDR=192.168.39.2:4999
~~~

<br/>

---

<br/>

When installing Undistro, a configuration file in the YAML format has to be specified. Such file can have any name as long as it is set in the environment variable _UND\_CONF_. Following is a snippet showing the file structure.

~~~yaml
global:
  undistroRepository: <REGISTRY_ADDRESS>
  undistroVersion: <DOCKER_IMAGE_TAG>
undistro-aws:
  enabled: <true | false>
  credentials:
    accessKeyID: <AWS_ID>
    secretAccessKey: <AWS_SECRET>
~~~

The field _undistroRepository_ is meant for the address of the Docker registry, while the image tag used for Undistro's images falls in the field _undistroVersion_.

When using Amazon's AWS cloud, the section _undistro-aws_ must be specified with the corresponding credentials, and the field _enabled_ with the value _true_. Setting this field as _false_ is the equivalent of not specifying the _undistro-aws_ section.

<br/>

---

<br/>

Another way in which this setup can be achieved is through the script _cluster.sh_, located in the _hack_ folder. This script is called when using the _make_ targets mentioned previously, working in a similar way, but without using environment variables. This script can be executed from anywhere within Undistro's source, taking flags as parameters which will direct it take a certain action. The flags are the following.

<br/>

- _h_ : Prints a help message;

- _b_ <ARG\>: Calls a script called _docker-build-e2e.sh_, transferring its argument to it. The  argument must be the registry address followd by the Undistro Docker tag, formatted as "<REGISTRY\_ADDRESS>:<DOCKER\_IMAGE_TAG>";

- _k_ : Creates a KinD cluster and a local Docker registry;

- _m_ <ARG\>: Creates a Minikube cluster with an internal registry, receiving the IP of Minikube's runtime as an argument;


<br/>

---

<br/>

Likewise, some examples of usage for the _cluster.sh_ script are displayed bellow. The first example shows how to create a KinD a cluster with a local registry.

~~~sh
$ ./hack/cluster.sh -k
~~~

In sequence, the coming example illustrates how to build the Docker images for Undistro and then push those in the registry.

~~~sh
$ ./hack/cluster.sh -b localhost:5000:latest
~~~

Finally, this example shows how to create a Minikube cluster whose runtime IP is 192.168.39.2, rebuild and push Undistro's Docker images.

~~~sh
$ ./hack/cluster.sh -m 192.168.39.2 -b 192.168.39.2:5000:latest
~~~

<br/>

---

<br/>



### Frontend

The frontend of Undistro is on its majority written in the Typescript language, a Javascript variant extending the language through static typing. This extension permits a more organized codebase as well as a better development workflow. Head over to the Typescript [website](https://www.typescriptlang.org/download) for information on how to obtain it.

Many external softwares from the Javascript ecosystem take part in building Undistro's frontend. Among the most important is React. This library intends to make the process of state change as fluid as possible, employing multiple mechanisms for this. One of them is the creation of components, which are reusable HTML elements to aggregate common behavior. Another one is the minimization of reloads necessary to present new information, in such a way that once a component switches state, only the component in question will be reloaded. Its syntax is heavily inspired by Javascript, taking advantage of knowledge already in place. To install React and to learn more, check out the [documentation](https://reactjs.org/docs/getting-started.html).

The bulk of the source is written according to the JSX style, a XML inspired embeddable set of elements which compile to Javascript, or in this case, to Typescript code, being used in parallel with React. It permits a greater cohesion between the processes of rendering and displaying UI elements, making the source much more readable. For in-depth information about JSX, visit Typescript's [page](https://www.typescriptlang.org/docs/handbook/jsx.html) and React's [documentation](https://reactjs.org/docs/jsx-in-depth.html).

In a similar manner, Next, a Javascript framework, brings many functionalities to the UI, UX and the development process as well. Along these, there is the Typescript integration with incremental type checking for improved speed, internationalized routing through automatic locale detection based on the _Accept-Language_ requisition header field, Server Side Rendering (SSR) architecture, image load optimization, built-in CSS and more. Installation instructions can be found in the Next [documentation](https://nextjs.org/docs/getting-started). Next also has a utility to compile JSX into Javascript, shipping with it enabled by default where no further configuration is required.

When it comes to the styling of Undistro's frontend, a technique put forth to better organize the styles of each view and to promote consistency across them is the creation of CSS variables. These variables are defined by way of SASS (Syntatically Awesome Style Sheets), a scripting language used as a preprocessing engine to generate CSS code, having direct interface with Javascript through its own API. More details about SASS are presented in its [documentation](https://sass-lang.com/documentation). This engine is also bundled with Next, in such a way that no manual setup is required once Next is installed.

Likewise, an additional library used in Undistro's GUI is called React Table. This library is a collection of extensible hooks for building tables, which do not interfere with the UI rendering. It doesn't bring with itself any table component, focusing on integrating with any theme or UI library already in place and to assist the creation of new ones. Check out its official [documentation](https://react-table.tanstack.com/docs/overview) to learn more about the library.


<br/>


## How to add a new provider

One of the goals Undistro strives to accomplish is to support all available cloud providers. This goal will require a never ending effort, given that as time passes new providers will emerge and old ones may fall out of use. In this section, the steps required to add a new provider to Undistro are discussed.

One of the first things required to include a working provider is to have a proper template dictating to Kubernetes how to manipulate the resources provided to it, in conjunction with some characteristics of the clusters such as network and pod configuration. Such templates are stored in the directory _undistro/pkg/fs/clustertemplates/<PROVIDER_NAME>_, in such a way that each provider will have a dedicated folder for it. In the case of a new provider, this folder has to be created.

Since Undistro has its own schema represented by a _Cluster_ type, which embeds Kubernetes' _TypeMeta_ and _ObjectMeta_ structs, these templates ought to be specified primarily by means of it. Such approach increases the coherence within Undistro's inner workings, further streamlining its development. 

As an example, bellow is displayed a section of a YAML template for the Amazon Elastic Compute cloud platform.

~~~yaml
kind: AWSMachineTemplate
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha4
metadata:
  name: "{{.Cluster.Name}}-cp-{{.Cluster.Status.LastUsedUID}}"
  namespace: "{{.Cluster.Namespace}}"
spec:
  template:
    spec:
      instanceType: "{{.Cluster.Spec.ControlPlane.MachineType}}"
      iamInstanceProfile: "control-plane.cluster-api-provider-aws.sigs.k8s.io"
      {{if .Cluster.Spec.InfrastructureProvider.SSHKey}}
      sshKeyName: "{{ .Cluster.Spec.InfrastructureProvider.SSHKey}}"
      {{end}}
      {{if .Cluster.Spec.ControlPlane.ProviderTags}}
      additionalTags:
        {{range $key, $value := .Cluster.Spec.ControlPlane.ProviderTags}}
        {{$key}}: {{$value | quote}}
        {{end}}
      {{end}}
      {{if .Cluster.Spec.ControlPlane.Subnet}}
      subnet:
        id: {{.Cluster.Spec.ControlPlane.Subnet}}
      {{end}}
~~~

This template is stored in the file _undistro/pkg/fs/clustertemplates/aws/ec2.yaml_, following the previously mentioned directory structure. In it, most of the YAML fields are filled according to the state stored in the _Cluster_ schema, save for the ones containing metadata of the API itself. Each provider will have its own YAML structure, but given the overlapping context between them, the values stored in the _Cluster_ type are likely to fit most if not all of them.

It's in these templates that the configuration for Kubernetes' Taints are located. Taints are a set of properties applied to nodes, which together with Tolerations and Node Affinity, dictate whether a pod will be attracted or repelled from such nodes. Although the properties available are the same regardless of the provider in question, the format of the names of these properties can have variations, what must be treated in the specification. In the case of AWS for example, Taints are formatted according to dash case, being written in the following manner: _this-is-a-taint_. However, the Kubernetes API refers to Taints according to camel case, where the previously mentioned Taint would be formatted as follows: _ThisIsATaint_.

Undistro provides a built-in function to treat this case, called _slugfyTaintEffect_, which can be invoked in the template by prepending the value with the _slugtaint_ identifier. Following is an illustration of this process.

~~~yaml
  # ...
  taints:
    {{range $element.Taints}}
    - key: {{.Key}}
      value: {{.Value}}
      effect: {{slugtaint .Effect}}
    {{end}}
  # ...
~~~

After completing the provider template, it is important to consider whether that provider requires some preliminary processing to be executed before the installation of one's clusters. If that's the case, said processing is to be written to a _main.go_ file, inside a dedicated directory within the _cmd_ path named after the provider plus a "-init" suffix. In other words, the path of such file has to follow this structure: _undistro/cmd/<PROVIDER_NAME>-init/main.go_.

This file is compiled into a standalone binary and then shipped as a Docker image to the provider prior to Undistro's installation, thus ensuring that such provider will be ready for it.

In order to deal with each provider's particularities, a folder can be created in the path _undistro/pkg/cloud_ to store any further configuration or setup files. Packages in such folder are sometimes sourced within the _main.go_ preprocessing file, but only there. Anywhere else in Undistro where provider specific functionality is required, the _cloud_ package must be employed. This package contains a file called _setup.go_, which exposes not only functions from each provider's API, but also some of its attributes. When adding a new provider, many resources can be exposed by including them within the _switch_ instructions already in place, given that the functions containing them have been implemented so as to generically cover provider-client interactions.

Lastly, a Helm chart for the newly provisioned provider must be created and placed under the _charts_ folder. For standardization purposes, provider charts have the string "undistro-" as part of the name, where the provider name is appended right after it. 

Such chart must contain the credentials required to authenticate with the provider's infrastructure, as well as Undistro's CRDs generated by Kubebuilder in a dedicated file within a folder called _crds_. Since Kubebuilder stores all the generated YAML definitions in a single file, the CRD specifications must be extracted from it, where the remaining values should also be placed into specific files each. This process is performed manually.

Furthermore, the chart must include a file containing provider specific configuration. Most providers include a template for this in their home page, frequently being named as _infrastructure.yaml_.

<br/>


## How to update the documentation

The project is documented in Markdown, a simple and straightforward markup language used to create plain-text documents with emphasis on readability. 

Due to its permissive licensing, there have been multiple publications of Markdown syntax specification. This project uses the CommonMark format, which characterizes itself as an unambiguous, highly compatible Markdown specification, having a wide variety of tools available for its parsing.

These characteristics allow the documentation to be converted into a HTML page and deployed as part of this website. Such conversion is made possible by 3 components.

<br/>

&nbsp &nbsp &nbsp &nbsp **micromark**: a state-machine based parser used to group the markdown document content into concrete tokens, being the fastest Javascript implementation of a CommonMark parser;

&nbsp &nbsp &nbsp &nbsp **remark**: a CommonMark processor supporting a wide range of plugins, wrapping around micromark ;

&nbsp &nbsp &nbsp &nbsp **react-markdown**: a React component which uses remark to handle CommonMark, dynamically updating the newly modified parts of the DOM instead of rebuilding it entirely;
<br/>
	
The source for the documentation can be found at _undistro/website/src/util_. There, in the _docs_ directory lies the text files displayed here. Each file contains a section and its contents, being named after the former. For small editions where just paragraphs are changed, only one of these files needs to be edited. However, in case headings are added or removed, the file _markdownNavigation.js_ must also be edited to reflect the changes, as well as the file _undistro/website/src/routes/docs/index.js_.

An Undistro specific formatting keyword is the _TagVersion_ HTML tag, which can be placed alongside titles with a given release number to colorize the text. Such tag is controlled according to a _type_ parameter, receiving the values _deprecated_ for red text or _version_ for blue. Bellow is a usage example such tag.

~~~markdown
# Feature Y <TagVersion type = "version"> Version 0.9.2 </TagVersion>
~~~

Any CommonMark parser can be used to see the rendered document, but in order to visualize it as an HTML page together with the whole Undistro website, the following dependencies have to be installed.

<br/>

&nbsp &nbsp &nbsp &nbsp **node.js**: an asynchronous event-driven Javascript runtime based on Chromium's V8 engine, used to deploy server-side programs; 

&nbsp &nbsp &nbsp &nbsp **npm**: a diverse database of Javascrit softwares, with CLI program used for retrieving and managing packages;
<br/>


These dependencies may be obtained through your package manager, or directly at [node](https://nodejs.org/en/download) and [npm's](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) downloads page.

Once these dependencies are installed, head over to the _undistro/website_ directory and run the command _npm install_, which will download and install all packages required to run the website. Afterwards, the command _npm start_ will compile the whole website and serve it locally at the port 3001.

Finally, open a browser and enter the URL _http://localhost:3001/docs_ to visualize the changes.

If the modifications are ready, publish them on Github and open a pull-request at [Undistro's repository](https://github.com/getupio-undistro/undistro/pulls).

**Warning!** Backticks (`) are not currently rendered in this document.

<br/>


## How all components communicate

Undistro's repository contais not only its own source code, but also some related files, as is the case with the _charts_ directory. The entire project structure is laid out as follows.

- _UI_ : Contains the source of Undistro's frontend;
- _apis_ : Stores the Undistro API and its versions;
- _bin_ : Where the compiled binaries are saved;
- _charts_ : Stores multiple Helm charts maintained by the Undistro team;
- _cmd_ : Has the main Go files for the CLIs;
- _config_ : Keeps configuration files generated by Kubebuilder;
- _controllers_ : Keeps generated Kubernetes' controllers and a few test files;
- _e2e_ : Contains files used for End-to-End testing;
- _examples_ : Stores YAML files describing how to use Undistro;
- _hack_ : Miscellaneous configuration files and helper scripts;
- _pkg_ : Stores the core functionality of each Undistro package;
- _testbin_ : Stores binary dependencies downloaded during testing, as well as shell scripts used for building and testing;
- _tilt\_modules_ : Contains Tilt configuration files for Undistro and for _cert-manager_ as well;
- _website_ : Keeps the source code for Undistro's website and this documentation;

As previously mentioned, the _charts_ directory is not part of Undistro's source. Such folder stores Helm charts of third-party components used by Undistro. Among them is Kyverno.

Undistro employes Kyverno for its control policies. Kyverno is a policy management engine built specifically for Kubernetes, where policies are represented as Kubernetes resources and can be defined through YAML files. These policies are built by matching the resource's kind, name or label selector, thus allowing cluster events to trigger certain actions.

In sequence is displayed a policy used by Undistro, named _deny-delete-kyverno_, and stored in the file _pkg/fs/policies/disallow-delete-kyverno.yaml_. Such policy covers all pods, as denoted by the _ClusterPolicy_ kind, having a single blocking rule called _block-deletes-for-kyverno-resources_. This rule denies deletion calls made from Kubernetes objects which posses the label _app.kubernetes.io/managed-by: kyverno_ as well as those whose role is not of _cluster-admin_ type. In case this rule is violated, the message "Deleting <OBJECT_KIND>/<OBJECT_NAME> is not allowed" is displayed. For more information on policies, have a look at Kyverno's [documentation](https://kyverno.io/docs/introduction/).

~~~yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-delete-kyverno
spec:
  validationFailureAction: enforce
  background: false
  rules:
    - name: block-deletes-for-kyverno-resources
      match:
        resources:
          selector:
            matchLabels:
              app.kubernetes.io/managed-by: kyverno
      exclude:
        clusterRoles:
          - cluster-admin
      validate:
        message: "Deleting {{request.oldObject.kind}}/{{request.oldObject.metadata.name}} is not allowed"
        deny:
          conditions:
            - key: "{{request.operation}}"
              operator: In
              value:
                - DELETE
~~~

Calico is another third-party component Undistro makes use of. The component is defined as a networking appliance for containers, virtual machines as well as host-based workloads, supporting multiple plataforms. Kubernetes by itself has no default networking mechanism and depends upon a CNI (Container Network Interface) plugin for network connectivity, what makes Calico a crucial component.

Furthermore, Calico is also capable of network policy management, enforcing which traffic is or is not allowed. This is important because by default, all pods can intercommunicate, what is not ideal in a production environment. Such policies are defined through YAML files, similar to Kyverno's, using label matching to identify pods as well. Undistro always applies these policies in the clusters it creates. To learn more about Calico, visit the official [documentation](https://docs.projectcalico.org/about/about-calico)

A third component used by Undistro is called cert-manager. This is a cloud-native component used to validate, emit and renew certificates, representing them as resource types in Kubernetes clusters. Since Undistro issues its own certificates, the configuration of cert-manager becomes rather trivial, consisting mainly of a dedicated Kubernetes namespace called _cert-manager-test_, an issuer of type _SelfSigned_ and lastly, a certificate with the secret name _selfsigned-cert-tls_. Following is a snippet of the cert-manager configuration.

~~~yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-test
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: test-selfsigned
  namespace: cert-manager-test
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: selfsigned-cert
  namespace: cert-manager-test
spec:
  dnsNames:
  - example.com
  secretName: selfsigned-cert-tls
  issuerRef:
    name: test-selfsignedx
~~~

The cert-manager [website](https://cert-manager.io/docs/configuration/selfsigned/) provides more in-depth information on certificates and issuers.

In order to communicate with Kubernetes clusters, Undistro makes use of the Cluster API. Kubernetes has built this interface to simplify the creation of automated solutions for provisioning, upgrading and management of its clusters. In the source tree, this API is used through the _capi_ alias, and by means of it multiple assets of Kubernetes cluster are manipulated, such as setting cluster namespaces, fetching individual cluster names, configuring the cluster network, etc. The [documentation](https://cluster-api.sigs.k8s.io) has more information on the use-cases of this API.

For the purpose of simplifying outside network traffic management, an Ingress controller called _ingress-nginx_ is used. This controller exposes routes through HTTP and its encrypted equivalent protocol, directing inbounding traffic to specific Kubernetes services. This routing is done through Nginx, a multi-purpose software containing the functionality of a web server, load balancer, reverse proxy and more. Check out Nginx's Ingress [page](https://www.nginx.com/products/nginx-ingress-controller/) for more information.

The point of using Nginx through Ingress is to take advantage of Kubernetes' unified configuration, in such a way that the service routes and whatnot can be set up declaratively through YAMLs, where the Ingress' engine will apply this configuration in its respective form to the Nginx server. The previously mentioned 443 and 80 ports, are used by this controller for HTTPS and HTTP traffic, as is conventional in such protocols.

A fifth component used by Undistro is Pinniped, a cluster authenticator based on the OIDC (Open ID Connect) protocol. This component is divided into two Helm charts: _pinniped-concierge_ and _pinniped-supervisor_. This first is used to validade JWT (JSON Web Tokens) issued by an OIDC server. The later is an OIDC issuer connecting a single provider to multiple clients, thus allowing cluster wide authentification. Further details can be found at the Pinniped [documentation](https://pinniped.dev/docs/).

Pinniped makes use of the port 6443 for its authentication service, which is exposed as an HTTPS TLS signed endpoint. This service allows access control over the cluster, redirecting valid calls to the Kubernetes API. Undistro currently supports Gitlab, Google and Azure's OIDC providers, but aspires to work with any provider in the future.

When it comes to load balancing, Kubernetes only provides support for cloud plataforms. For this reason, a component named _MetalLB_ is used. This component permits the creation of a local load banlancer by means of a specif IP range delegated to it, overcomming Kubernetes' limitation with conventional network tools. For more information, check out _MetalLB_'s [website](https://metallb.universe.tf/concepts/).

All these components are integrated in Undistro, being fetched and statically linked to it during compilation. Helm is responsible for downloading each component into the _charts_ directory, being invoked through the Go's generate build instruction. Said instructions are placed in the file _fs.go_ at the _pkg/fs_ directory.

In a similar fashion, these charts are shipped with Undistro through the embed instruction, permitting Undistro to update them automatically whenever new versions are released.

<br/>


## Connectivity

When it comes to network configuration, Undistro requires a certain set of ports to be accessible via the network. In case a firewall is in place, it must be configured to allow requests from the ports 80, 443 and 6443.

Furthermore, given that Undistro has its own registry for storing and distributing images, it's very important that such [registry](registry.undistro.io) is always reachable, since it is used to verify and download new versions of Undistro components.

