import { instance } from '@/api'
import i18n from '@/i18n'

const { t } = i18n.global

export const getOverviewInfo = (params: {
	domain: string
	start_time: number
	end_time: number
}) => {
	return instance.get('/overview', { params })
}

export const getFailedList = (params: { domain: string; start_time: number; end_time: number }) => {
	return instance.get('/overview/failed', { params })
}

export const getSendQueueList = () => {
	return instance.get('/postfix_queue/list')
}

export const getSendQueueInfo = (params: { queue_id: string }) => {
	return instance.get('/postfix_queue/queue_info', { params })
}

export const resendQueue = (params: { queue_ids: string[] }) => {
	return instance.post('/postfix_queue/flush_by_id', params, {
		fetchOptions: {
			loading: t('overview.api.loading.resendQueue'),
			successMessage: true,
		},
	})
}

export const deleteSendQueue = (params: { queue_ids: string[] }) => {
	return instance.post('/postfix_queue/delete_by_id', params, {
		fetchOptions: {
			loading: t('overview.api.loading.deleteQueue'),
			successMessage: true,
		},
	})
}

export const getSendQueueConfig = () => {
	return instance.get('/postfix_queue/get_config')
}

export const setSendQueueConfig = (params: Record<string, string>) => {
	return instance.post('/postfix_queue/set_all_config', params, {
		fetchOptions: {
			loading: t('overview.api.loading.setQueueConfig'),
			successMessage: true,
		},
	})
}

export const clearSendQueue = (params = {}) => {
	return instance.post('/postfix_queue/delete', params, {
		fetchOptions: {
			loading: t('overview.api.loading.clearQueue'),
			successMessage: true,
		},
	})
}
