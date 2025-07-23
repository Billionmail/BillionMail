import { loadEnv } from '@rsbuild/core'
import serverConfig from './config'

/**
 * @description 获取环境变量
 * @param key
 * @returns
 */
export function getEnv(key: string) {
	const { parsed } = loadEnv()
	return parsed[key]
}

/**
 * @description 获取服务器配置
 * @returns
 */
export function getServer() {
	const name = getEnv('SERVER_NAME') || '192.168.66.124'
	return serverConfig[name]
}
