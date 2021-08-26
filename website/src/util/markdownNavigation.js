const titleNavigation = [
	{
		title: 'Introduction',
		number: '1',
		subtitle: [
			{
				title: 'What is UnDistro?',
				number: '1.1',
				id: '#what-is-UnDistro'
			},
			{
				title: 'Architecture',
				number: '1.2',
				id: '#architecture'
			}
		],
		id: '#1---introduction'
	},
	{
		title: 'Quick Start',
		number: '2',
		subtitle: [],
		id: '#2---quick-start'
	},
	{
		title: 'Installing UnDistro',
		number: '3',
		subtitle: [
			{
				title: 'Prepare environment',
				number: '3.1',
				id: '#prepare-environment'
			},
			{
				title: 'Existing Cluster',
				number: '3.2',
				id: '#existing-cluster'
			},
			{
				title: 'Kind',
				number: '3.3',
				id: '#kind'
			},
			{
				title: 'Download UnDistro CLI',
				number: '3.4',
				id: '#download-undistro-cli'
			},
			{
				title: 'Create the configuration file',
				number: '3.5',
				id: '#create-the-configuration-file'
			},
			{
				title: 'Initialize the management cluster',
				number: '3.6',
				id: '#initialize-the-management-cluster'
			},
			{
				title: 'Upgrade a provider into management cluster',
				number: '3.7',
				id: '#upgrade-a-provider-into-management-cluster'
			}
		],
		id: '#3---installing-undistro'
	},
	{
		title: 'Configuration',
		number: '4',
		subtitle: [
			{
				title: 'Reference',
				number: '4.1',
				id: '#reference'
			}
		],
		id: '#4---configuration'
	},
	{
		title: 'Providers',
		number: '5',
		subtitle: [
			{
				title: 'Configure',
				number: '5.1',
				id: '#configure'
			},
			{
				title: 'Flavors supported',
				number: '5.2',
				id: '#flavors-supported'
			},
			{
				title: 'VPC',
				number: '5.3',
				id: '#VPC'
			},
			{
				title: 'Create SSH Key pair on AWS',
				number: '5.4',
				id: '#create-SSH-Key-pair-on-AWS'
			},
			{
				title: 'Connecting to the nodes via SSH',
				number: '5.5',
				id: '#connecting-to-the-nodes-via-ssh'
			},
			{
				title: 'Consuming existing AWS infrastructure',
				number: '5.6',
				id: '#consuming-existing-aws-infrastructure'
			}
		],
		id: '#5---providers'
	},
	{
		title: 'Cluster',
		number: '6',
		subtitle: [
			{
				title: 'Specification',
				number: '6.1',
				id: '#specification'
			},
			{
				title: 'Create a cluster',
				number: '6.2',
				id: '#create-a-cluster'
			},
			{
				title: 'Delete a cluster',
				number: '6.3',
				id: '#delete-a-cluster'
			},
			{
				title: 'Consuming existing infrastructure',
				number: '6.4',
				id: '#consuming-existing-infrastructure'
			},
			{
				title: 'Get cluster kubeconfig',
				number: '6.5',
				id: '#get-cluster-kubeconfig'
			},
			{
				title: 'See cluster events',
				number: '6.6',
				id: '#see-cluster-events'
			},
			{
				title: 'Convert the created cluster into a management cluster',
				number: '6.7',
				id: '#convert-the-created-cluster-into-a-management-cluster'
			},
			{
				title: 'Check cluster',
				number: '6.8',
				id: '#check-cluster'
			},
			{
				title: 'A special thanks',
				number: '6.9',
				id: '#a-special-thanks'
			}
		],
		id: '#6---cluster'
	},
	{
		title: 'Identity',
		number: '7',
		subtitle: [
			{
				title: 'Overview',
				number: '7.1',
				id: '#overview'
			},
			{
				title: 'Minimal Identity Configuration',
				number: '7.2',
				id: '#minimal-identity-configuration'
			},
			{
				title: 'Authenticating via CLI',
				number: '7.3',
				id: '#authenticating-via-cli',
				subtitle: [
					{
						title: 'Adding an user cluster permission',
						number: '7.3.1',
						id: '#adding-an-user-cluster-permission'
					}
				]
			},
			{
				title: 'Authenticating via Web UI (Comming soon)',
				number: '7.4',
				id: '#authenticating-via-web-ui'
			},
		],
		id: '#7---identity'
	},
	{
		title: 'Policies',
		number: '8',
		subtitle: [
			{
				title: 'Default policies',
				number: '8.1',
				id: '#default-policies'
			},
			{
				title: 'Network policy',
				number: '8.2',
				id: '#network-policy'
			},
			{
				title: 'Default policies management',
				number: '8.3',
				id: '#default-policies-management'
			},
			{
				title: 'Applying customized policies',
				number: '8.4',
				id: '#applying-customized-policies'
			}
		],
		id: '#8---policies'
	},
	{
		title: 'Helm Release',
		number: '9',
		subtitle: [
			{
				title: 'Specification',
				number: '9.1',
				id: '#specification'
			},
			{
				title: 'Create Helm release',
				number: '9.2',
				id: '#create-helm-release'
			},
			{
				title: 'Delete Helm release',
				number: '9.3',
				id: '#delete-helm-release'
			},
			{
				title: 'Check Helm release',
				number: '9.4',
				id: '#check-helm-release'
			}
		],
		id: '#9---helm-release'
	},
	{
		title: 'Community',
		number: '10',
		subtitle: [],
		id: '#10---community'
	},
	{
		title: 'Development',
		number: '11',
		subtitle: [
			{
				title: 'How to setup the development environment',
				number: '11.1',
				subtitle: [
					{
						title: 'Backend',
						number: '11.1.1',
						id: '#backend'
					},
					{
						title: 'Frontend',
						number: '11.1.2',
						id: '#frontend'
					}
				],
				id: '#how-to-setup-the-development-environment'
			},
			{
				title: 'How to add a new provider',
				number: '11.2',
				id: '#how-to-add-a-new-provider'
			},
			{
				title: 'How to update the documentation',
				number: '11.3',
				id: '#how-to-update-the-documentation'
			},
			{
				title: 'How all components communicate',
				number: '11.4',
				id: '#how-all-components-communicate',
				subtitle: [
					{
						title: 'Connectivity',
						number: '11.4.1',
						id: '#connectivity'
					}
				]
			}
		],
		id: '#11---development'
	},
	{
		title: 'Glossary',
		number: '12',
		subtitle: [
			{
				title: 'Management Cluster',
				number: '12.1',
				id: '#management-cluster'
			},
			{
				title: 'Provider Components',
				number: '12.2',
				id: '#provider-components'
			},
			{
				title: 'Infrastructure Provider',
				number: '12.3',
				id: '#infrastructure-provider'
			},
			{
				title: 'Core Provider',
				number: '12.4',
				id: '#core-provider'
			}
		],
		id: '#12---glossary'
	}
]

export default titleNavigation
