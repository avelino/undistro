class Secret {
  http: any

  constructor (httpWrapper: any) {
    this.http = httpWrapper
  }

  async list (secretRef: string) {
    const url = `namespaces/undistro-system/clusters/management/proxy/api/v1/namespaces/undistro-system/secrets/${secretRef}`
    const res = await this.http.get(url)
    return res.data
  }
}

export default Secret