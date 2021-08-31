import { FC } from 'react'
import cn from 'classnames'
import './index.scss'

type CheckboxType = {
  value: boolean,
  disabled?: boolean,
  onChange: Function
}

const Checkbox: FC<CheckboxType> = ({
  value,
  disabled,
  onChange
}) => {
  const style = cn('checkbox', {
    'checkbox--checked': value,
    'checkbox--disabled': disabled
  })

  const handleCheck = () => {
    if (!disabled) onChange(!value)
  }

  return (
    <div className={style}>
      <span onClick={handleCheck}>
        <i className='icon-check' />
      </span>
    </div>
  )
}

export default Checkbox
