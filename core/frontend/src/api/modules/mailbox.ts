import { instance } from '@/api'
import i18n from '@/i18n'

const { t } = i18n.global

export const getMailboxList = (params: {
	page: number
	page_size: number
	domain: string | null
	keyword?: string
}) => {
	return instance.get('/mailbox/list', { params })
}

type MailboxParams = {
	full_name: string
	domain: string
	password: string
	active: number
	isAdmin: number
	quota: number
}

export const createMailbox = (params: MailboxParams) => {
	return instance.post('/mailbox/create', params, {
		fetchOptions: {
			loading: t('mailbox.api.loading.creating'),
			successMessage: true,
		},
	})
}

export const createBatchMailbox = (params: {
	domain: string
	prefix: string
	count: number
	quota: number
}) => {
	return instance.post('/mailbox/batch_create', params, {
		fetchOptions: {
			loading: t('mailbox.api.loading.creating'),
			successMessage: true,
		},
	})
}

export const updateMailbox = (params: MailboxParams) => {
	return instance.post('/mailbox/update', params, {
		fetchOptions: {
			loading: t('mailbox.api.loading.updating'),
			successMessage: true,
		},
	})
}

export const deleteMailbox = (params: { emails: string[] }) => {
	return instance.post('/mailbox/delete', params, {
		fetchOptions: {
			loading: t('mailbox.api.loading.deleting'),
			successMessage: true,
		},
	})
}

export const exportMailbox = (params: { domain: string }) => {
	return instance.post('/mailbox/export', params, {
		responseType: 'blob',
		fetchOptions: {
			loading: t('mailbox.api.loading.exporting'),
			successMessage: true,
		},
	})
}

export const importMailbox = (params: { file_data: string; file_type: string }) => {
	return instance.post('/mailbox/import', params, {
		fetchOptions: {
			loading: t('mailbox.api.loading.importing'),
			successMessage: true,
		},
	})
}
