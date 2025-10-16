import { instance } from '@/api'
import i18n from '@/i18n'
import type { SuspendParams } from '@/views/contacts/suspend/types/base'

const { t } = i18n.global

export const getSuspendList = (params: SuspendParams) => {
	return instance.get('/abnormal_recipient/list', { params })
}

export const getAutoScan = () => {
	return instance.get('/abnormal_recipient/check_switch')
}

export const deleteSuspend = (params: { id: number }) => {
	return instance.post('/abnormal_recipient/delete', params, {
		fetchOptions: {
			loading: t('contacts.suspend.api.loading.deleting'),
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
			loading: t('contacts.suspend.api.loading.scanning'),
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
				loading: t('contacts.suspend.api.loading.clearing'),
				successMessage: true,
			},
		}
	)
}

export const setAutoScan = (params: { oper: number }) => {
	return instance.post('/abnormal_recipient/set_check_switch', params, {
		fetchOptions: {
			loading: t('contacts.suspend.api.loading.setting'),
			successMessage: true,
		},
	})
}
