import { instance } from '@/api'
import i18n from '@/i18n'

const { t } = i18n.global

export const getSmtpList = () => {
	return instance.get('/relay/list')
}

type SmtpForm = {
	rtype: string
	remark: string
	smtp_name: string
	sender_domains: string[]
	relay_host: string
	relay_port: number
	auth_user: string
	auth_password: string
	active: number
}

export const addSmtp = (params: SmtpForm) => {
	return instance.post('/relay/add', params, {
		fetchOptions: {
			successMessage: true,
			loading: t('smtp.api.loading.adding'),
		},
	})
}

export const editSmtp = (params: Partial<SmtpForm> & { id: number }) => {
	return instance.post('/relay/edit', params, {
		fetchOptions: {
			successMessage: true,
			loading: t('smtp.api.loading.editing'),
		},
	})
}

export const testSmtp = (params: {
	sender_domains: string[]
	relay_host: string
	relay_port: number
	auth_user: string
	auth_password: string
}) => {
	return instance.post('/relay/test_connection', params, {
		fetchOptions: {
			successMessage: true,
			loading: t('smtp.api.loading.testing'),
		},
	})
}

export const deleteSmtp = (params: { id: number }) => {
	return instance.post('/relay/delete', params, {
		fetchOptions: {
			successMessage: true,
			loading: t('smtp.api.loading.deleting'),
		},
	})
}

export const getUnbindDomains = () => {
	return instance.get('/relay/get_unbound_domains')
}
