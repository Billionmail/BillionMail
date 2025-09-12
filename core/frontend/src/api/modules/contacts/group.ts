import i18n from '@/i18n'
import { instance } from '@/api'
import { GroupParams } from '@/views/contacts/group/types/base'

const { t } = i18n.global

export const getGroupList = (params: GroupParams) => {
	return instance.get('/contact/group/list', { params })
}

export const getGroupAll = () => {
	return instance.get('/contact/group/all')
}

export const getGroupInfo = (params: { group_id: number }) => {
	return instance.get('/contact/group/info', { params })
}

export const createGroup = (data: {
	create_type: number
	name: string
	description: string
	double_optin: number
	file_data?: string
	file_type?: string
}) => {
	return instance.post('/contact/group/create', data, {
		fetchOptions: {
			loading: t('contacts.group.loading.createGroup'),
			successMessage: true,
		},
	})
}

export const updateGroup = (data: { group_id: number; name: string }) => {
	return instance.post('/contact/group/update', data, {
		fetchOptions: {
			loading: t('contacts.group.loading.updateGroup'),
			successMessage: true,
		},
	})
}

export const deleteGroup = (data: { group_ids: number[] }) => {
	return instance.post('/contact/group/delete', data, {
		fetchOptions: {
			loading: t('contacts.group.loading.deleteGroup'),
			successMessage: true,
		},
	})
}

export const getContactCount = (data: { group_ids: number[] }) => {
	return instance.post('/contact/group/contact_count', data)
}

export const exportGroup = (data: {
	format: string
	include_unsubscribe: boolean
	group_ids: number[]
	export_type: number
}) => {
	return instance.post('/contact/group/export', data, {
		fetchOptions: {
			loading: t('contacts.group.loading.exportGroup'),
			successMessage: true,
		},
	})
}

export const saveSubscribeSetting = (data: {
	group_id: number
	double_optin: number
	send_welcome_email: number
	welcome_subject: string
	thank_you_subject: string
	welcome_mail_html: string
	welcome_mail_drag: string
	success_url: string
	confirm_subject: string
	confirm_mail_html: string
	confirm_mail_drag: string
	confirm_url: string
	already_url: string
}) => {
	return instance.post('/contact/group/update', data, {
		fetchOptions: {
			loading: t('contacts.group.loading.saveSettings'),
			successMessage: true,
		},
	})
}
