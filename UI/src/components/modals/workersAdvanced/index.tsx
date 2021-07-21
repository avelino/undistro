import React, { FC, useState } from 'react'
import Select from '@components/select'
import Toggle from '@components/toggle'
import Input from '@components/input'
import Button from '@components/button'
import AsyncSelect from '@components/asyncSelect'
import FormSlider from '@components/formSlider'
import { TypeOption, TypeWorkersAdvanced } from '../../../types/cluster'
import './index.scss'

const WorkersAdvanced: FC<TypeWorkersAdvanced> = ({
  groupIdOptions,
  groupId,
  setGroupId,
  replicas,
  setReplicas,
  cpu,
  setCpu,
  getCpu,
  getMem,
  memory,
  setMemory,
  machineTypes,
  setMachineTypes,
  getMachineTypes,
  autoScale,
  setAutoScale,
  maxSize,
  setMaxSize,
  minSize,
  setMinSize,
  keyTaint,
  setKeyTaint,
  valueTaint,
  setValueTaint,
  effectValue,
  setEffectValue,
  effect,
  keyLabel,
  setKeyLabel,
  valueLabel,
  setValueLabel,
  keyProv,
  setKeyProv,
  valueProv,
  setValueProv,
  taints,
  providers,
  labels,
  deleteTaints,
  deleteProviders,
  deleteLabels,
  handleActionTaints,
  handleActionLabel,
  handleActionProv,
  handleAction,
  subnet,
  setSubnet
}) => {
  const [showTaint, setShowTaint] = useState<boolean>(false)
  const [showLabel, setShowLabel] = useState<boolean>(false)
  const [showProv, setShowProv] = useState<boolean>(false)

  const formReplica = (e: React.FormEvent<HTMLInputElement>) => {
    setReplicas(parseInt(e.currentTarget.value) || 0)
  }

  const formMax = (e: React.FormEvent<HTMLInputElement>) => {
    setMaxSize(parseInt(e.currentTarget.value) || 0)
  }

  const formMin = (e: React.FormEvent<HTMLInputElement>) => {
    setMinSize(parseInt(e.currentTarget.value) || 0)
  }

  const formSubnet = (e: React.FormEvent<HTMLInputElement>) => {
    setSubnet(e.currentTarget.value)
  }

  const formCpu = (option: TypeOption | null) => {
    setCpu(option)
  }

  const formGroup = (option: TypeOption | null) => {
    setGroupId(option)
  }

  const formMem = (option: TypeOption | null) => {
    setMemory(option)
  }

  const formMachineTypes = (option: TypeOption | null) => {
    setMachineTypes(option)
  }


  return (
    <div className='workers-advanced-container'>
      <h3 className="title-box">Workers</h3>
      <div className='group-id'>
        <Select options={groupIdOptions} value={groupId} onChange={formGroup} label='group ID' />
      </div>
      <div className='input-container'>
        <Input value={replicas} onChange={formReplica} type='text' label='replicas' />
        <Input type='text' value={subnet} onChange={formSubnet} label='Subnet' />
        <AsyncSelect value={cpu} onChange={formCpu} loadOptions={getCpu} label='CPU' />
        <AsyncSelect value={memory} onChange={formMem} loadOptions={getMem} label='mem' />
        <AsyncSelect value={machineTypes} onChange={formMachineTypes} loadOptions={getMachineTypes} label='machineType' />
      </div>

      <div className='auto-scale-container'>
        <Toggle value={autoScale} onChange={() => setAutoScale(!autoScale)} label='enable auto scale' />

        <div className='size-inputs'>
          <Input type='text' value={minSize} onChange={formMin} label='min size' />
          <Input type='text' value={maxSize} onChange={formMax} label='max size' />
        </div>
      </div>

      <div className='boxes-container'>
        <div className='box-content'>
          <p className='title'>Taints</p>
          <ul>
            {(taints || []).map((elm: any, i) => {
              return (
                <li key={elm}>
                  <p>taint-{i}</p>
                  <i onClick={() => deleteTaints?.(elm)} className='icon-close' />
                </li>
              )
            })}
          </ul>
          <i className='icon-plus' onClick={() => setShowTaint(!showTaint)}/>
          {showTaint && 
            <FormSlider
              direction='left'
              title='Add taints'
              key={keyTaint!}
              setKey={setKeyTaint!}
              value={valueTaint!}
              setValue={setValueTaint!}
              taint={effectValue}
              setTaint={setEffectValue}
              options={effect}
              select
              handleAction={() => handleActionTaints?.()}
              handleClose={() => setShowTaint(!showTaint)}
            />}
        </div>

        <div className='box-content'>
          <p className='title'>Labels</p>
          <ul>
            {(labels || []).map((elm: any, i) => {
              return (
                <li key={elm}>
                  <p>label-{i}</p>
                  <i onClick={() => deleteLabels?.(elm)} className='icon-close' />
                </li>
              )
            })}
          </ul>
          <i className='icon-plus' onClick={() => setShowLabel(!showLabel)}/>
          {showLabel && 
            <FormSlider
              direction='right'
              title='Add labels'
              key={keyLabel!}
              setKey={setKeyLabel!}
              value={valueLabel!}
              setValue={setValueLabel!}
              handleAction={() => handleActionLabel?.()}
              handleClose={() => setShowLabel(!showLabel)}
            />}
        </div>

        <div className='box-content'>
          <p className='title'>Provider tags</p>
          <ul>
          <ul>
            {(providers || []).map((elm: any, i) => {
              return (
                <li key={elm}>
                  <p>provTag-{i}</p>
                  <i onClick={() => deleteProviders?.(elm)} className='icon-close' />
                </li>
              )
            })}
          </ul>
          </ul>
          <i className='icon-plus' onClick={() => setShowProv(!showProv)}/>
          {showProv && 
            <FormSlider
              direction='right'
              title='Add provider tags'
              key={keyProv!}
              setKey={setKeyProv!}
              value={valueProv!}
              setValue={setValueProv!}
              handleAction={() => handleActionProv?.()}
              handleClose={() => setShowProv(!showProv)}
            />}
        </div>
      </div>
      <Button size='small' type='gray' children='Save group' onClick={() => handleAction()} />
    </div>
  )
}

export default WorkersAdvanced