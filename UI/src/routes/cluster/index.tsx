/* eslint-disable react-hooks/exhaustive-deps */
import { ClusterDetails } from '@components/details'
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import Api from 'util/api'
import { useHistory } from 'react-router'

export default function ClusterRoute() {
  const [data, setData] = useState<any>()
  const [accessKey, setAccesskey] = useState<string>('')
  const [secret, setSecret] = useState<string>('')
  const [region, setRegion] = useState<string>('')
  const [provider, setProvider] = useState<string>('')
  const [session, setSession] = useState<string>('')
  const params = useParams<any>()
  const history = useHistory()

  const getData = () => {
    Api.Cluster.get(params.namespace, params.clusterName)
      .then(elm => setData(elm))
  }

  const getSecrets = (secretRef: string) => {
    Api.Secret.list(secretRef).then(res => {
      setAccesskey(atob(res.data.accessKeyID))
      setSecret(atob(res.data.secretAccessKey))
      setRegion(atob(res.data.region))
      setSession(res.data.sessionToken)
    })
  }

  const getProviders = () => {
    Api.Provider.list('providers').then(res => {
      const newArray = res.items.filter((elm: any) => {
        return elm.spec.category.includes('infra')
      })
      setProvider(newArray[0].metadata.name)
      getSecrets(newArray[0].spec.secretRef.name)
      return newArray
    })
  }

  useEffect(() => {
    getData()
    getProviders()
  }, [])

  return data?(
    <div className="home-page-route">
      <ClusterDetails
        data={{
          generalClusterName: data.metadata.name,
          generalProvider: provider,
          generalDefaultRegion: region,
          generalAccessKeyId: accessKey,
          generalSecretAccessKey: secret,
          generalSessionToken: session,
          generalNamespace: data.metadata.namespace,
          bastionUserDefaultBlocksCidr: (data.spec.bastion.allowedCIDRBlocks || [])[0],
          infraFlavor: data.spec.infrastructureProvider.flavor,
          infraK8sVersion: data.spec.kubernetesVersion,
          infraProvider: data.spec.infrastructureProvider.name,
          infraSshKey: data.spec.infrastructureProvider.sshKey,
          infraRegion: data.spec.infrastructureProvider.region,
          k8sApiServerPort: data.spec.network.apiServerPort,
          k8sPodsRanges: data.spec.network.pods,
          k8sServiceDomain: data.spec.network.serviceDomain,
          k8sServiceRanges: data.spec.network.services,
          infraNetworkId: data.spec.network.vpc.id,
          infraNetworkCidrBlock: data.spec.network.vpc.cidrBlock,
          infraNetworkZone: data.spec.network.vpc.zone,
          bastionDisableIngressRules: data.spec.bastion.ingress,
          bastionEnabled: data.spec.bastion.enabled,
          k8sNetworkMultiZone: data.spec.network.multiZone
        }}
        onCancel={() => history.push('/')}
        onSave={data => {
          console.log(data)
        }}
      />
    </div>
  ) : null
}