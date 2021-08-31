import { FC } from 'react'
import './index.scss'

const BreadCrumb: FC = () => {
  return (
    <div className='bread-crumb'>
      <p>Clusters</p>
      <i className='icon-arrow-right' />
      <p>Cluster Name Exemple</p>
      <i className='icon-arrow-right' />
      <p>Test</p>
    </div>
  )
}

export default BreadCrumb
