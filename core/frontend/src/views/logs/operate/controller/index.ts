import { instance } from '@/api'

export const getLogsList = async (params: { page: number; page_size: number; keyword: string }) => {
	return await instance.get('/operation_log/list', { params })
}

export const getLogsType = async () => {
	return await instance.get('/operation_log/type_list')
}
