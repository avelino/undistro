import React, { FC } from 'react'
import cn from 'classnames'
import './index.scss'

type Props = {
  label?: string
  value?: boolean
  onChange?: Function
}

const Toggle: FC<Props> = ({ label, value, onChange }) => {
  const style = cn('toggle', {
    '--right': !value,
    '--left': value
  })

  return (
    <div className="toggle-container">
      <label>{label}</label>
      <div
        className={style}
        onClick={() => {
          if (onChange) {
            onChange(!value)
          }
        }}
      />
    </div>
  )
}

export default Toggle
