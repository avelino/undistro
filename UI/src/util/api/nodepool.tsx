class Node {
  http: any

  constructor(httpWrapper: any) {
    this.http = httpWrapper
  }


  async list () {
    const url = `namespaces/undistro-system/clusters/management/proxy/apis/cluster.x-k8s.io/v1alpha4/machinepools`
    const res = await this.http.get(encodeURI(url))
    return res.data
  }


  async get (namespace: string, name: string) {
    const url = `namespaces/undistro-system/clusters/management/proxy/apis/cluster.x-k8s.io/v1alpha4/namespaces/${namespace}/machinepools/${name}`
    const res = await this.http.get(url)
    return res.data
  }

  async delete(namespace: string, clusterName: string) {
    const url = `namespaces/undistro-system/clusters/management/proxy/apis/cluster.x-k8s.io/v1alpha4/namespaces/${namespace}/machinepools?labelSelector=cluster.x-k8s.io/cluster-name=${clusterName}`
    const res = await this.http.delete(encodeURI(url))
    return res.data
  }

  async create() {
    console.log('created')

    return
  }
}

export default Node
