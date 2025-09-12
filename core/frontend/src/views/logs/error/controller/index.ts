import { instance } from '@/api'

export const getErrorLogs = async () => {
	return await instance.get('/operation_log/output/latest')
}
