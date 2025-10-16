import { isNumber } from './is'

export const isDev = import.meta.env.DEV

export const apiUrl: string = import.meta.env.SERVER.address

// Server prefix
export const apiUrlPrefix: string = import.meta.env.API_URL_PREFIX

/**
 * @description Byte conversion with specified unit
 * @param bytes Number of bytes
 * @param isUnit Whether to display unit
 * @param fixed Decimal point position
 * @param endUnit End unit
 * @returns Formatted string with unit
 */
export const getByteUnit = (
	bytes: number = 0,
	isUnit: boolean = true,
	fixed: number = 2,
	endUnit: string = ''
): string => {
	if (!isNumber(bytes)) {
		bytes = Number(bytes)
		if (isNaN(bytes)) return ''
	}

	const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB', 'BB', 'NB', 'DB']
	const base = 1024
	let value = bytes

	for (let i = 0; i < units.length; i++) {
		const unit = units[i]
		const formattedValue = fixed === 0 ? Math.round(value).toString() : value.toFixed(fixed)

		if (endUnit && unit === endUnit.trim()) {
			return isUnit ? `${formattedValue} ${unit}` : formattedValue
		}

		if (value < base) {
			return isUnit ? `${formattedValue} ${unit}` : formattedValue
		}

		value /= base
	}

	return '--'
}

/**
 * @description 首字母大写
 * @param val
 * @returns
 */
export const capitalizeFirstLetter = (val: string) => {
	return val
		.split(' ')
		.map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
		.join(' ')
}

/**
 * @description Validate a URL
 */
export function isUrl(url: string): boolean {
	const urlRegex =
		/^(https?:\/\/)?((([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})|((\d{1,3}\.){3}\d{1,3}))(:\d{1,5})?(\/.*)?$/
	return urlRegex.test(url)
}

/**
 * @description Generate a random password that contains lowercase letters, uppercase letters and numbers
 * @param len Password length, default is 8
 */
export function getRandomPassword(len = 16) {
	// Ensure the password length is at least 3 to include all required character types
	len = Math.max(len, 3)

	const lowerChars = 'abcdefghijklmnopqrstuvwxyz'
	const upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	const numbers = '0123456789'
	const allChars = lowerChars + upperChars + numbers

	// Ensure at least one lowercase letter, one uppercase letter and one number
	let pwd = ''
	pwd += lowerChars.charAt(Math.floor(Math.random() * lowerChars.length))
	pwd += upperChars.charAt(Math.floor(Math.random() * upperChars.length))
	pwd += numbers.charAt(Math.floor(Math.random() * numbers.length))

	// Generate remaining random characters
	for (let i = 3; i < len; i++) {
		const index = Math.floor(Math.random() * allChars.length)
		pwd += allChars[index]
	}

	// Shuffle password characters to avoid fixed patterns
	return pwd
		.split('')
		.sort(() => Math.random() - 0.5)
		.join('')
}
