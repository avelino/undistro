import React from 'react'
import './index.scss'
import titleNavigation from 'Util/markdownNavigation'
import MarkdownAccordion from '../../components/molecules/markdownAccordion'
import { MDXProvider } from '@mdx-js/react'
import Introduction from 'Util/docs/introduction.md'
import QuickStart from 'Util/docs/quickStart.md'
import Install from 'Util/docs/installingUndistro.md'
import Config from 'Util/docs/configuration.md'
import Providers from 'Util/docs/providers.md'
import Cluster from 'Util/docs/cluster.md'
import Identity from 'Util/docs/identity.md'
import Policies from 'Util/docs/policies.md'
import Helm from 'Util/docs/helm.md'
import Community from 'Util/docs/community.md'
import Glossary from 'Util/docs/glossary.md'
import TagVersion from 'Components/atoms/tagVersion'

export default function DocsRoute () {
	return (
		<div className="docs-container">
			<div className="banner">
				<h1>Docs</h1>
			</div>
			<div className="markdown-container">
				<div className="navigation">
					<div className="sticky">
						<MarkdownAccordion navigation={titleNavigation} />
					</div>
				</div>
				<div className="content">
					<MDXProvider
						components={{ TagVersion }}
					>
						<Introduction />
						<QuickStart />
						<Install />
						<Config />
						<Providers />
						<Cluster />
						<Identity />
						<Policies />
						<Helm />
						<Community />
						<Glossary />
					</MDXProvider>
				</div>
			</div>
		</div>
	)
}
