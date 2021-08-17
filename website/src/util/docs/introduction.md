# 1 - Introduction

## What is UnDistro (will be in version 1.0.0)?

UnDistro is an enterprise software that automates multicloud, on-prem, and edge operations with a single management UI.

UnDistro automates thousands of Kubernetes clusters across multi-cloud, on-prem and edge with unparalleled resilience. Deploy, manage and run multiple Kubernetes clusters with our platform. On your preferred infrastructure.

UnDistro Kubernetes Platform is directly integrated with leading cloud providers, and runs even in your own datacenter.

By providing managed Kubernetes clusters for your infrastructure, UnDistro makes Kubernetes as easy as it can be. UnDistro empowers you to take advantage of all the advanced features that Kubernetes has to offer and increases the speed, flexibility and scalability of your deployment workflow.

UnDistro provides live updates of your Kubernetes cluster without disrupting your daily business.

## Architecture

The overarching architecture of UnDistro is centered around a "management plane". This plane is expected to serve as a single interface upon which administrators can create, scale, upgrade, and delete Kubernetes clusters. At a high level view, the management plane + created clusters should look something like this:

![Image of Architecture](https://raw.githubusercontent.com/getupio-undistro/undistro/main/website/src/assets/images/arch.jpg)
&nbsp;

&nbsp;
