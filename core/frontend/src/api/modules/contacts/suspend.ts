import { instance } from '@/api'
import type { SuspendParams } from '@/views/contacts/suspend/types/base'

export const getSuspendList = (params: SuspendParams) => {
	return instance.get('/abnormal_recipient/list', { params })
}

export const getAutoScan = () => {
	return instance.get('/abnormal_recipient/check_switch')
}

export const deleteSuspend = (params: { id: number }) => {
	return instance.post('/abnormal_recipient/delete', params, {
		fetchOptions: {
			loading: 'Deleting, please wait...',
			successMessage: true,
		},
	})
}

export const getScanLogs = () => {
	return instance.post('/abnormal_recipient/get_scan_log')
}

export const scanGroup = (params: { group_id: number; oper: number }) => {
	return instance.post('/abnormal_recipient/check_group', params, {
		fetchOptions: {
			loading: 'Scanning, please wait...',
			successMessage: true,
		},
	})
}

export const clearSuspend = () => {
	return instance.post(
		'/abnormal_recipient/clear_abnormal',
		{},
		{
			fetchOptions: {
				loading: 'Clearing, please wait...',
				successMessage: true,
			},
		}
	)
}

export const setAutoScan = (params: { oper: number }) => {
	return instance.post('/abnormal_recipient/set_check_switch', params, {
		fetchOptions: {
			loading: 'Setting, please wait...',
			successMessage: true,
		},
	})
}
