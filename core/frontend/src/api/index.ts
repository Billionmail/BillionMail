import axios, { AxiosRequestConfig } from 'axios'
import router from '@/router'
import { useUserStore } from '@/store'
import { apiUrlPrefix, isObject, Message } from '@/utils'

interface FetchOptions {
	prefix: string
	loading: string
	loadFn: () => void
	cancelResInterceptor: boolean
}

const instance = axios.create({
	baseURL: apiUrlPrefix,
	timeout: 600000,
	headers: {
		'Content-Type': 'application/json',
	},
	fetchOptions: {
		prefix: '/api',
		successMessage: false,
	},
})

const whitePathList = ['/login']

// 存储所有请求的 AbortController
const controllerStore = new Map<string, AbortController>()

// 生成唯一请求标识
const generateReqKey = (config: AxiosRequestConfig): string => {
	const { method, url, params, data } = config
	return `${method}-${url}-${JSON.stringify(params)}-${JSON.stringify(data)}`
}

// 添加请求到控制器存储
const addController = (config: AxiosRequestConfig): void => {
	const key = generateReqKey(config)

	// 如果已有相同请求则取消前一个
	if (controllerStore.has(key)) {
		controllerStore.get(key)?.abort()
		controllerStore.delete(key)
	}

	// 创建新控制器
	const controller = new AbortController()
	config.signal = controller.signal
	controllerStore.set(key, controller)
}

// 从存储中移除控制器
const removeController = (config: AxiosRequestConfig): void => {
	const key = generateReqKey(config)
	if (controllerStore.has(key)) {
		controllerStore.delete(key)
	}
}

// 请求拦截器 增加token
instance.interceptors.request.use(config => {
	addController(config)
	const { headers, url } = config
	if (!whitePathList.includes(url || '')) {
		const userStore = useUserStore()
		headers.Authorization = `Bearer ${userStore.login.token}`
	}
	return config
})

// 请求拦截器 处理请求前缀
instance.interceptors.request.use(config => {
	const { fetchOptions } = config
	if (isObject<FetchOptions>(fetchOptions)) {
		config.url = `${fetchOptions.prefix}` + config.url
	}
	return config
})

// 请求拦截器 处理请求前缀
instance.interceptors.request.use(config => {
	const { fetchOptions } = config
	if (isObject<FetchOptions>(fetchOptions) && fetchOptions.loading) {
		const { close } = Message.loading(fetchOptions.loading)
		fetchOptions.loadFn = close
	}
	return config
})

// 成功、失败处理
instance.interceptors.response.use(
	response => {
		removeController(response.config)

		const { fetchOptions } = response.config
		const { code, data, msg, success } = response.data || {}

		if (fetchOptions?.cancelResInterceptor) {
			return Promise.resolve(data)
		}

		if (fetchOptions?.loadFn) {
			fetchOptions.loadFn()
		}

		if (response.data.type === 'application/octet-stream') {
			const url = window.URL.createObjectURL(new Blob([response.data]))
			const link = document.createElement('a')
			link.href = url
			const disposition = response.headers['content-disposition']
			const filename = disposition
				? decodeURIComponent(disposition.split('filename=')[1])
				: 'downloaded_file'
			link.setAttribute('download', filename)
			document.body.appendChild(link)
			link.click()
			document.body.removeChild(link)
			window.URL.revokeObjectURL(url)
			return Promise.resolve(data)
		}

		if (code === 0 && success) {
			if (fetchOptions?.successMessage) {
				Message.success(msg)
			}
			return Promise.resolve(data)
		}
		if (!success && msg) {
			Message.error(msg, {
				close: true,
			})
		}
		if (code === 401) {
			const userStore = useUserStore()
			userStore.resetLoginInfo()
			router.push('/login')
		}
		return Promise.reject(response.data)
	},
	error => {
		if (!axios.isCancel(error)) {
			removeController(error.config || {})
		}
		return Promise.reject(error)
	}
)

// 取消所有进行中的请求
const clearPendingRequests = (): void => {
	controllerStore.forEach((controller, key) => {
		controller.abort()
		controllerStore.delete(key)
	})
}

export { instance, clearPendingRequests }
