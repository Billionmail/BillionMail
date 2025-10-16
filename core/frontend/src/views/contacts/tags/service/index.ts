import { instance } from '@/api'
import { i18n } from '@/i18n'
import type { TagParams } from '../types'

const { t } = i18n.global

export const getTagList = (params: TagParams) => {
	return instance.get('/tags/list', { params })
}

export const getTagAll = (params: { group_id?: number }) => {
	return instance.get('/tags/all', { params })
}

export const createTag = (params: { name: string; group_id: number }) => {
	return instance.post('/tags/create', params, {
		fetchOptions: {
			loading: t('contacts.tags.loading.creating'),
			successMessage: true,
		},
	})
}

export const deleteTag = (params: { id: number }) => {
	return instance.post('/tags/delete', params, {
		fetchOptions: {
			loading: t('contacts.tags.loading.deleting'),
			successMessage: true,
		},
	})
}

export const updateTag = (params: { id: number; name: string }) => {
	return instance.post('/tags/update', params, {
		fetchOptions: {
			loading: t('contacts.tags.loading.updating'),
			successMessage: true,
		},
	})
}

export const bulkSetTag = (params: {
	group_id: number
	tag_ids: number[]
	data: string
	mark_include: number
}) => {
	return instance.post('/tags/batch_contacts', params, {
		fetchOptions: {
			loading: t('contacts.tags.loading.bulkSetting'),
			successMessage: true,
		},
	})
}
