import axios from 'axios'
import Nodepool from './nodepool'
import Cluster from './cluster'
import Provider from './provider'
import Secret from './secret'

const HOST = window.location.hostname

const BASE_URL = `http://${HOST}/uapi/v1`

const httpWrapper = axios.create({
  baseURL: BASE_URL + '/',
  timeout: 600000
})

const Api = {
  Nodepool: new Nodepool(httpWrapper),
  Cluster: new Cluster(httpWrapper),
  Provider: new Provider(httpWrapper),
  Secret: new Secret(httpWrapper)
}

export default Api
