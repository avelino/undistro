import { useState } from 'react'
import Select from '@components/select'
import Input from '@components/input'
import Button from '@components/button'

import './index.scss'

export default function RbacPage() {
  const [role, setRole] = useState<string>('')
  const [namespaces, setNamespaces] = useState<string>()
  const [roleName, setRoleName] = useState<string>()
  const [apiGroups, setApiGroups] = useState<string>()
  const [resources, setResources] = useState<string>()
  const [verbs, setVerbs] = useState<string>()
  const [ruleName, setRuleName] = useState<string>()

  const handleAction = () => {
    console.log('Save Changes')
  }

  const formNamespaces = (e: React.FormEvent<HTMLInputElement>) => {
    setNamespaces(e.currentTarget.value)
  }

  const formRoleName = (e: React.FormEvent<HTMLInputElement>) => {
    setRoleName(e.currentTarget.value)
  }

  const formApiGroups = (e: React.FormEvent<HTMLInputElement>) => {
    setApiGroups(e.currentTarget.value)
  }

  const formResources = (e: React.FormEvent<HTMLInputElement>) => {
    setResources(e.currentTarget.value)
  }

  const formVerbs = (e: React.FormEvent<HTMLInputElement>) => {
    setVerbs(e.currentTarget.value)
  }

  const formRuleName = (e: React.FormEvent<HTMLInputElement>) => {
    setRuleName(e.currentTarget.value)
  }
  

  const options = [
    { label: 'Role', value: 'Role' },
    { label: 'Cluster Role', value: 'ClusterRole' },
    { label: 'Role Biding', value: 'RoleBiding' },
    { label: 'Cluster Role Biding', value: 'ClusterRoleBiding' },
  ]

  return (
    <div className='rbac-route'>
      <div className='content'>
        <h3>Role Definition</h3>
        <Select 
          options={options} 
          value={role}
          onChange={setRole}
          className='rbac-select'
          label='Role Type'
        />
        <Input 
          placeholder='insert one or more namespaces here' 
          label='Namespaces'
          value={namespaces}
          onChange={formNamespaces}
        />
        <Input 
          placeholder='choose a name for this role' 
          label='Role unique ID'
          value={roleName}
          onChange={formRoleName} 
        />

        <h3>Rules Definition</h3>
        <Input 
          placeholder='insert one or more groups here' 
          label='apiGroups'
          value={apiGroups}
          onChange={formApiGroups}
        />
        <Input 
          placeholder='insert one or more resources here' 
          label='Resources'
          value={resources}
          onChange={formResources}
        />
        <Input 
          placeholder='insert one or more verbs here' 
          label='Verbs'
          value={verbs}
          onChange={formVerbs}
        />
        <Input 
          placeholder='insert one or more verbs here' 
          label='Rule unique ID'
          value={ruleName}
          onChange={formRuleName}
        />

        <div className='button-container'>
          <Button variant='black' size='large' children='Cancel' />
          <Button onClick={handleAction} size='large' children='Save Changes' />
        </div>
      </div>
    </div>
  )
}