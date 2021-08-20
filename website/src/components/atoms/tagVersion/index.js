/* eslint-disable react/prop-types */
import React from 'react'
import cn from 'classnames'
import './index.scss'

const TagVersion = ({ children, type }) => {
	const style = cn('tag',
		`tag--${type}`
	)

	return (
		<p className={style}>{children}</p>
	)
}

export default TagVersion
