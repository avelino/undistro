#!/usr/bin/env bash
#
# Script to setup an local Kubernetes cluster for now offering two local engines,
# Minikube and KinD.

set -o errexit -o errtrace -o pipefail;

function exit_and_inform {
	err_n=$1
	case $err_n in
		0)
			echo "Error: The <h>, <m> and <k> flags are mutually exclusive." 1>&2
			;;
		1)
			echo "Error: The <h> and <b> flags are mutually exclusive." 1>&2
			;;
		2)
			echo "Error: No git project, unable to find <docker-build-e2e.sh>." 1>&2
			;;
		3)
			echo "Error: Malformed build string." 1>&2
			;;
		4)
			print_long_help
			exit 0
			;;
		*)
			echo "Usage: $(basename $0) [-h] [-b <registry_address>:<docker_tag>] [-k | -m <minikube_ip>]"
			;;
	esac
	exit 1
}

function print_long_help {
	cat <<- EOF
		Usage: $(basename $0) <OPTIONS>
		The options are:
	EOF
	flags=("h" "b <registry_address>:<docker_tag>" "k" "m <minikube_ip>")
	f_desc=(
		"Print this help message."
		"Calls the <docker-build-e2e.sh> build script and passes the registry address with the Undistro Docker tag to it."
		"Creates a KinD cluster and a local Docker registry."
		"Creates a Minikube cluster with an internal registry, receiving the IP of Minikube's runtime."
	)
	for i in $(seq 0 $((${#flags[*]} - 1))); do
		printf "  %s%s \n\t  %s\n\n" "-" "${flags[$i]}" "${f_desc[$i]}"
	done
	echo
}

## Minikube only.
function start_minikube {
	minikube start --addons="registry" \
		--install-addons=true \
		--driver=docker \
		--container-runtime=containerd \
		--docker-opt="-p 80:80/tcp -p 443:443/tcp -p 6443:6443/tcp" \
		--ports=6443 \
		--insecure-registry="$mk_addr:$reg_port" \
		--extra-config="kubelet.node-labels='ingress-ready=true'" \
		--extra-config="kubelet.container-runtime-endpoint='http://$mk_addr:$reg_port'"
}

function call_build_script {
	proj_root=$(git rev-parse --show-toplevel)
	if test -n "$proj_root"; then
		match_arg=$(echo $b_addr_and_tag | grep -Eo "[a-z0-9.-]+:([0-9]+:)?[a-z0-9-]+")
		echo $match_arg
		if test -n "$match_arg"; then
			addr=$(echo $b_addr_and_tag | sed -E "s/:[a-z0-9]+$//g")
			tag=$(echo $b_addr_and_tag | sed "s/.*://g")
			echo $addr
			echo $tag
			. $proj_root/testbin/docker-build-e2e.sh $addr $tag
		else
			exit_and_inform 3
		fi
	else
		exit_and_inform 2
	fi
}

## KinD only.
function create_registry_container {
	# create registry container unless it already exists
	running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
	if test "${running}" != 'true'; then
		docker run \
			-d --restart=always -p "${reg_port}:5000" --name "${reg_name}" \
			registry:2
	fi
}

## KinD only.
function print_registry_host {
	if test "${kind_network}" = "bridge"; then
		reg_name="$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "${reg_name}")"
	fi
	echo "Registry Host: ${reg_name}"
}

## KinD only.
function create_kind_cluster_and_enable_registry {
KIND_API_PORT=${KIND_API_PORT:-6443}
cat <<EOF | kind create cluster --name "${KIND_CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerPort: ${KIND_API_PORT}
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:${reg_port}"]
EOF
}

## KinD only.
function apply_kube_config {
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
}

## KinD only.
function connect_docker_to_kind_network {
	if test "${kind_network}" != "bridge"; then
		containers=$(docker network inspect ${kind_network} -f "{{range .Containers}}{{.Name}} {{end}}")
		needs_connect="true"
		for c in $containers; do
			if test "$c" = "${reg_name}"; then
				needs_connect="false"
			fi
		done
		if test "${needs_connect}" = "true"; then               
			docker network connect "${kind_network}" "${reg_name}" || true
		fi
	fi
}

## KinD only.
function setup_kind {
	# desired cluster name; default is "kind"
	KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
	kind_version=$(kind version)
	kind_network='kind'
	reg_name='kind-registry'
	case "${kind_version}" in
		"kind v0.7."* | "kind v0.6."* | "kind v0.5."*)
			kind_network='bridge'
			;;
	esac
	create_registry_container
	print_registry_host
	create_kind_cluster_and_enable_registry
	apply_kube_config
	connect_docker_to_kind_network
}



if test $# -eq 0; then
	exit_and_inform
fi
o_h=0
o_m=0
o_k=0
o_b=0
while getopts "hm:kb:" o; do
    case "$o" in
        h)
			o_h=1
			exit_and_inform 4
            ;;
        m)
			(test $o_k -ne 0 && test $o_h -ne 0) && exit_and_inform 0
			mk_addr=$OPTARG
			o_m=1
            ;;
        k)
			(test $o_m -ne 0 && test $o_h -ne 0) && exit_and_inform 0
			o_k=1
            ;;
        b)
			(test $o_h -ne 0) && exit_and_inform 1
			b_addr_and_tag=$OPTARG
			o_b=1
            ;;
        *)
			exit_and_inform
            ;;
    esac
done
shift $((OPTIND - 1))

reg_port=5000
if test $o_m -eq 1; then
	start_minikube
elif test $o_k -eq 1; then
	setup_kind
fi
if test $o_b -eq 1; then
	call_build_script
fi
