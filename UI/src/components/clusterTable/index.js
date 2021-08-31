import React, { useState, useEffect, useRef } from 'react'
import Classnames from 'classnames'
import Api from 'util/api'
import Checkbox from '@components/checkbox'
import './index.scss'
import { useClickOutside } from 'hooks/useClickOutside'
import { useDisclosure } from 'hooks/useDisclosure'
import {
  ChangeVersionAlert,
  DeleteClusterAlert,
  PauseClusterAlert,
  ResumeClusterAlert
} from '@components/clusterActionAlert'
import { useHistory } from 'react-router-dom'

const ASC = 'asc'
const DES = 'des'

const SortIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 20 20"
    fill="currentColor"
  >
    <path d="M5 12a1 1 0 102 0V6.414l1.293 1.293a1 1 0 001.414-1.414l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L5 6.414V12zM15 8a1 1 0 10-2 0v5.586l-1.293-1.293a1 1 0 00-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L15 13.586V8z" />
  </svg>
)

const emptyCluster = {
  age: '',
  clusterGroups: '',
  flavor: '',
  machines: undefined,
  name: '',
  pause: undefined,
  provider: '',
  status: '',
  version: '',
  isEmpty: true
}

const Table = props => {
  const [key, setKey] = useState('')
  const [order, setOrder] = useState('')
  const [version, setVersion] = useState([])
  const [value, setValue] = useState(false)
  const getK8sVersion = () => {
    Api.Provider.list('flavors')
      .then(res => res.items.map(elm => setVersion(elm.spec.supportedK8SVersions)))
  }

  useEffect(() => {
    getK8sVersion()
  }, []) 

  const sortedRows = props.data.sort((a, b) => {
    if (!key) return 0
    if (a[key] > b[key]) return order === ASC ? -1 : 1
    if (a[key] < b[key]) return order === ASC ? 1 : -1

    return 0
  })

  const filledRows =
    sortedRows.length >= 20
      ? sortedRows
      : [...sortedRows, ...Array(20 - sortedRows.length).fill(emptyCluster)]

  return (
    <table className="table">
      <thead>
        <tr>
          <td className='checkbox-row'>
            <Checkbox value={value} onChange={setValue} />
          </td>
          <td />
          {props.header.map(elm => (
            <td key={elm.name}>
              <ColumnHeader data={elm} />
              <button
                className="icon-button"
                onClick={() => {
                  setKey(elm.field)
                  setOrder(
                    !order || order === DES || key !== elm.field ? ASC : DES
                  )
                }}
              >
                <SortIcon />
              </button>
            </td>
          ))}
        </tr>
      </thead>
      <tbody>
        {filledRows.map((elm, i) => {
          return (
            <Row
              onChange={props.onChange}
              header={props.header}
              key={i}
              data={elm}
              icon={elm.pause ? 'icon-play' : 'icon-stop'}
              status={elm.status}
              pause={elm.pause}
              isEmpty={elm.isEmpty}
              version={version}
              currentVersion={elm.version}
            />
          )
        })}
      </tbody>
    </table>
  )
}

const ColumnHeader = props => {
  const [order, setOrder] = useState(true)

  const handleChangeOrder = value => {
    setOrder(value)
  }

  return (
    <div className="header">
      <label>{props.data.name}</label>
      <i onClick={() => handleChangeOrder(!order)} className="" />
    </div>
  )
}

const Row = props => {
  const [keys, setKeys] = useState([])
  const [show, setShow] = useState(false)
  const [pause, setPause] = useState(props.pause)
  const [status, setStatus] = useState(props.status)
  const [value, setValue] = useState(false)
  const history = useHistory()
  const menuRef = useRef(null)

  const redirectToCluster = () => {
    history.push(`/cluster/${props.data.clusterGroups}/${props.data.name}`)
  }

  useClickOutside(menuRef, () => {
    setShow(false)
  })

  const [
    isPauseClusterAlertOpen,
    closePauseClusterAlert,
    openPauseClusterAlert
  ] = useDisclosure()

  const [
    isResumeClusterAlertOpen,
    closeResumeClusterAlert,
    openResumeClusterAlert
  ] = useDisclosure()

  const [
    isChangeVersionAlertOpen,
    closeChangeVersionAlert,
    openChangeVersionAlert
  ] = useDisclosure()

  const [
    isDeleteClusterAlertOpen,
    closeDeleteClusterAlert,
    openDeleteClusterAlert
  ] = useDisclosure()

  useEffect(() => {
    setStatus(props.status)
  }, [props.status])

  useEffect(() => {
    setPause(props.pause)
  }, [props.pause])

  useEffect(() => {
    const headers = props.header.map(elm => elm.field)
    setKeys(Object.keys(props.data).filter(elm => headers.includes(elm)))
  }, [props.data, props.header])

  const handlePause = () => {
    const payload = {
      spec: {
        paused: !pause
      }
    }

    Api.Cluster.put(payload, props.data.clusterGroups, props.data.name).then(data => {
      setPause(data.spec.paused)
      setStatus(data.spec.paused ? 'Paused' : 'Ready')
      closePauseClusterAlert(false)
      closeResumeClusterAlert(false)
    })
  }

  const handleChangeVersion = (version) => {
    const payload = {
      spec: {
        kubernetesVersion: version
      }
    }

    Api.Cluster.put(payload, props.data.clusterGroups, props.data.name).then(_ => {
      closeChangeVersionAlert(true)
    })
  }

  const handleDelete = () => {
    Api.Cluster.delete(props.data.clusterGroups, props.data.name).then(_ => {
      console.log(`Deleted cluster ${props.data.name}.`)
      closeDeleteClusterAlert(true)
    })
  }

  return (
    <tr>
      <td className="checkbox-row">
        <Checkbox value={value} onChange={setValue} />
      </td>
      <td className="select-row">
        {isChangeVersionAlertOpen && (
          <ChangeVersionAlert
            heading={props.data.name}
            isOpen={isChangeVersionAlertOpen}
            onActionConfirm={version => handleChangeVersion(version)}
            onDismiss={closeChangeVersionAlert}
            versions={props.version}
            currentVersion={props.currentVersion}
          />
        )}
        {isDeleteClusterAlertOpen && (
          <DeleteClusterAlert
            heading={props.data.name}
            isOpen={isDeleteClusterAlertOpen}
            onActionConfirm={handleDelete}
            onDismiss={closeDeleteClusterAlert}
          />
        )}
        <PauseClusterAlert
          heading={props.data.name}
          isOpen={isPauseClusterAlertOpen}
          onActionConfirm={handlePause}
          onDismiss={closePauseClusterAlert}
        />
        <ResumeClusterAlert
          heading={props.data.name}
          isOpen={isResumeClusterAlertOpen}
          onActionConfirm={handlePause}
          onDismiss={closeResumeClusterAlert}
        />
        <i
          onClick={() => {
            if (!props.isEmpty) setShow(!show)
          }}
          className={`icon-dots ${props.isEmpty ? 'icon-dots-empty' : ''}`}
        />
        {show && (
          <ul ref={menuRef}>
            <li
              onClick={() => {
                setShow(false)
                pause ? openResumeClusterAlert() : openPauseClusterAlert()
              }}
            >
              <i className={Classnames(pause ? 'icon-play' : 'icon-stop')} />
              {pause ? <p>Resume UnDistro</p> : <p>Pause UnDistro</p>}
            </li>
            <li
              onClick={() => {
                setShow(false)
                openChangeVersionAlert()
              }}
            >
              <i className="icon-arrow-solid-up" /> <p>Update K8s</p>
            </li>
            <li
              onClick={() => {
                setShow(false)
                redirectToCluster()
              }}
            >
              <i className="icon-settings" /> <p>Cluster Settings</p>
            </li>
            <li
              onClick={() => {
                setShow(false)
                openDeleteClusterAlert()
              }}
            >
              <i className="icon-close-solid" /> <p>Delete Cluster</p>
            </li>
          </ul>
        )}
      </td>
      {keys.map(key => {
        let cellColorClassName = ''
        let statusCellColorName = ''

        if (['name', 'status'].includes(key)) {
          if (status === 'Paused') cellColorClassName = 'cluster-paused'
          else if (status === 'Error') cellColorClassName = 'cluster-error'
        }

        if (key === 'status') {
          switch (status) {
            case 'Ready':
              statusCellColorName = 'status-cell-ready'
              break

            case 'Provisioning':
              statusCellColorName = 'status-cell-provisioning'
              break

            default:
              statusCellColorName = ''
          }
        }

        return (
          <td
            key={key}
            className={`${cellColorClassName} ${statusCellColorName}`}
          >
            <div>
              <span>{key === 'status' ? status : props.data[key]}</span>
            </div>
          </td>
        )
      })}
    </tr>
  )
}

export default Table
