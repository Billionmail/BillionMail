import { instance } from '@/api'
import i18n from '@/i18n'

const { t } = i18n.global

export const getDomainList = (params: { page: number; page_size: number; keyword: string }) => {
	return instance.get('/domains/list', { params })
}

export const getDomainAll = () => {
	return instance.get('/domains/all')
}

export const getDomainIpCommand = () => {
	return instance.post('/multi_ip_domain/apply')
}

type DomainParams = {
	domain: string
	quota: number
	mailboxes: number
	email: string
	urls: string[]
	hostname: string
	outbound_ip: string
	hasbrandinfo?: number
}

export const createDomain = (params: DomainParams) => {
	return instance.post('/domains/create', params, {
		fetchOptions: {
			loading: t('domain.api.loading.creating'),
			successMessage: true,
		},
	})
}

export const updateDomain = (params: DomainParams) => {
	return instance.post('/domains/update', params, {
		fetchOptions: {
			loading: t('domain.api.loading.updating'),
			successMessage: true,
		},
	})
}

export const deleteDomain = (params: { domain: string }) => {
	return instance.post('/domains/delete', params, {
		fetchOptions: {
			loading: t('domain.api.loading.deleting'),
			successMessage: true,
		},
	})
}

export const setSsl = (params: { domain: string; certificate: string; key: string }) => {
	return instance.post('/domains/set_ssl', params, {
		fetchOptions: {
			loading: t('domain.api.loading.settingSSL'),
			successMessage: true,
		},
	})
}

export const getSsl = (params: { domain: string }) => {
	return instance.get('/domains/get_ssl', { params })
}

export const freshDnsRecord = (params: { domain: string }) => {
	return instance.post('/domains/fresh_dns_records', params, {
		fetchOptions: {
			loading: t('domain.api.loading.refreshingDns'),
			successMessage: true,
		},
	})
}

export const applyCert = (params: { domain: string }) => {
	return instance.post('/ssl/apply_cert', params, {
		fetchOptions: {
			loading: t('domain.api.loading.applyingCert'),
			successMessage: true,
		},
	})
}

export const setDefaultDomain = (params: { domain: string }) => {
	return instance.post('/domains/set_default_domain', params, {
		fetchOptions: {
			loading: t('domain.api.loading.settingDefault'),
			successMessage: true,
		},
	})
}

export const initAiConfiguration = (params: { domain: string; urls: string[] }) => {
	return instance.post('/askai/project/create', params, {
		fetchOptions: {
			loading: t('domain.api.loading.settingBrandInfo'),
			successMessage: true,
		},
	})
}

export const testConnection = (params: { domain: string; outbound_ip: string }) => {
	return instance.post('/multi_ip_domain/test', params, {
		fetchOptions: {
			loading: t('domain.api.loading.testingConnection'),
			successMessage: true,
		},
	})
}

export const checkAiConfiguration = () => {
	return instance.post('/askai/supplier/status')
}
