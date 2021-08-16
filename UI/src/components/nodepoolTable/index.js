import React, { useState, useEffect, useRef } from 'react'
import Api from 'util/api'
import './index.scss'
import { useClickOutside } from 'hooks/useClickOutside'
import { useDisclosure } from 'hooks/useDisclosure'
import { DeleteNodepoolAlert } from '@components/nodepoolActionAlert'
import { useHistory } from 'react-router'

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

const AddIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 20 20"
    fill="currentColor"
  >
    <path
      fillRule="evenodd"
      d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z"
      clipRule="evenodd"
    />
  </svg>
)

const emptyCluster = {
  name: '',
  type: '',
  replicas: '',
  version: '',
  labels: '',
  taints: '',
  age: '',
  status: '',
  isEmpty: true
}

const Table = props => {
  const [key, setKey] = useState('')
  const [order, setOrder] = useState('')

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
          const isLast =
            filledRows.filter(({ type }) => type === elm.type).length === 1

          return (
            <Row
              header={props.header}
              key={i}
              data={elm}
              icon={elm.pause ? 'icon-play' : 'icon-stop'}
              status={elm.status}
              pause={elm.pause}
              isEmpty={elm.isEmpty}
              isLast={isLast}
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
  const menuRef = useRef(null)
  const history = useHistory()

  useClickOutside(menuRef, () => {
    setShow(false)
  })

  const [
    isDeleteNodepoolAlertOpen,
    closeDeleteNodepoolAlert,
    openDeleteNodepoolAlert
  ] = useDisclosure()

  useEffect(() => {
    const headers = props.header.map(elm => elm.field)
    setKeys(Object.keys(props.data).filter(elm => headers.includes(elm)))
  }, [props.data, props.header])

  const handleDelete = (namespace = 'undistro-system') => {
    Api.Nodepool.delete(namespace, props.data.name).then(_ => {
      console.log(`Deleted cluster ${props.data.name}.`)
    })
  }

  const handleRedirect = () => {
    let nodepool = ''
    if (props.data.type === "Control Plane") nodepool = 'controlPlane'
    else nodepool = 'worker'

    history.push(`/${nodepool}/undistro-system/${props.data.name}`)
  }

  const isControlPlane = props.data.provider === 'aws'
  // const isControlPlane = props.data.type === 'controlPlane'

  return (
    <tr>
      <td className="select-row">
        {isDeleteNodepoolAlertOpen && (
          <DeleteNodepoolAlert
            type={props.data.type}
            isLast={props.isLast}
            heading={props.data.name}
            isOpen={isDeleteNodepoolAlertOpen}
            onActionConfirm={handleDelete}
            onDismiss={closeDeleteNodepoolAlert}
          />
        )}

        <i
          onClick={() => {
            if (!props.isEmpty) setShow(!show)
          }}
          className={`icon-dots ${props.isEmpty ? 'icon-dots-empty' : ''}`}
        />
        {show && (
          <ul ref={menuRef}>
            <li className="separate-context-item">
              <AddIcon /> <p>Create Nodepool</p>
            </li>
            <li>
              <i onClick={() => handleRedirect()} className="icon-settings" /> <p>Nodepool Settings</p>
            </li>
            <li
              className={isControlPlane ? 'disabled-option' : ''}
              onClick={() => {
                if (!isControlPlane) {
                  setShow(false)
                  openDeleteNodepoolAlert()
                }
              }}
            >
              <i className="icon-close-solid" /> <p>Delete Nodepool</p>
            </li>
          </ul>
        )}
      </td>
      {keys.map(key => {
        let cellColorClassName = ''
        let statusCellColorName = ''

        if (['name', 'status'].includes(key)) {
          if (props.status === 'Paused') cellColorClassName = 'cluster-paused'
          else if (props.status === 'Error')
            cellColorClassName = 'cluster-error'
        }

        if (key === 'status') {
          switch (props.status) {
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
              <span>{key === 'status' ? props.status : props.data[key]}</span>
            </div>
          </td>
        )
      })}
    </tr>
  )
}

export default Table
