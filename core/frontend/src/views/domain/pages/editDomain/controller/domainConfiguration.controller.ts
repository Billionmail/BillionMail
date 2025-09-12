import { instance } from '@/api'
import { instanceOptions } from './companyProfile.controller'
import { getEditDomainStoreData } from '../store'
import { getByteUnit, Message, isUrl, isObject } from '@/utils'
import { initAiConfiguration } from '@/api/modules/domain'
import { useGlobalStore } from '@/store'
import i18n from '@/i18n'
import { MailDomain } from '@/views/domain/interface'

/**
 * @description Check if this domain has brand info
 */
// export async function checkDomainBrandInfo(domain: string) {
// 	try {
// 		const res = (await instance.post('/askai/project/get_project_status', { domain })) as {
// 			create_status: boolean
// 			status: boolean
// 		}
// 		if (res.update_time != 0) {
// 			return true
// 		} else {
// 			return false
// 		}
// 	} catch (error) {
// 		console.warn(error)
// 		return false
// 	}
// }

/**
 * @description Get domain detail
 */
export async function getDomainDetail(domain: string) {
	const {
		domainTit,
		domainIp,
		hostname,
		quota,
		unit,
		mailboxes,
		catch_email,
		hasGotDomainConfiguration,
		urls,
	} = getEditDomainStoreData()
	if (hasGotDomainConfiguration.value) return
	try {
		const res = await instance.get('/domains/list', {
			params: { keyword: domain, page: 1, page_size: 1 },
		})
		if (isObject<{ list: MailDomain[] }>(res)) {
			const { list } = res
			const quotaAndUnit = getByteUnit(list[0].quota, true, 2).split(' ')
			domainTit.value = list[0].domain
			domainIp.value = list[0].multi_ip_domains?.outbound_ip || ''
			hostname.value = list[0].a_record
			quota.value = quotaAndUnit[0]
			unit.value = quotaAndUnit[1]
			mailboxes.value = list[0].mailboxes
			catch_email.value = list[0].email
			urls.value =
				list[0].urls && list[0].urls.length > 0 && list[0].urls[0] != ''
					? list[0].urls
					: [`https://${domain}`]

			await configurationStatus(domain)
			hasGotDomainConfiguration.value = true
		}
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Configuration status
 */
export async function configurationStatus(domain: string) {
	const { brandInfo, createdBrandInfo } = getEditDomainStoreData()
	try {
		const res = (await instance.post('/askai/project/get_project_status', { domain })) as {
			create_status: boolean
			status: boolean
		}
		brandInfo.value = res.status
		createdBrandInfo.value = res.create_status
	} catch (error) {
		console.warn(error)
	}
}

export async function testConnection() {
	const { domainTit, domainIp } = getEditDomainStoreData()
	if (domainIp.value == '') {
		Message.error(i18n.global.t('domain.edit.domainConfiguration.validation.setDedicatedIpFirst'))
		return
	}

	try {
		await instance.post(
			'/multi_ip_domain/test',
			{
				domain: domainTit.value,
				outbound_ip: domainIp.value,
			},
			{
				fetchOptions: {
					loading: i18n.global.t('domain.edit.domainConfiguration.api.testingConnection'),
					successMessage: true,
				},
			}
		)
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Update domain
 */
export async function updateDomain() {
	const {
		domainTit,
		domainIp,
		hostname,
		quota,
		unit,
		urls,
		mailboxes,
		catch_email,
		// brandInfo,
		// waitAndCheckDomainStatusRef,
		// configurationStatus,
	} = getEditDomainStoreData()
	const quotaParam = calcBaseUnits(Number(quota.value), unit.value)

	try {
		await instance.post(
			'/domains/update',
			{
				domain: domainTit.value,
				mailboxes: mailboxes.value,
				mailboxQuota: quotaParam,
				quota: quotaParam,
				rateLimit: 1,
				active: 1,
				email: catch_email.value,
				urls: urls.value,
				outbound_ip: domainIp.value,
				hostname: hostname.value,
			},
			instanceOptions
		)
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Create brand info
 */
export async function createBrandInfo() {
	const { waitAndCheckDomainStatusRef, domainTit, urls, hasGotDomainConfiguration } =
		getEditDomainStoreData()
	const globalStore = useGlobalStore()
	hasGotDomainConfiguration.value = false
	if (urls.value.length == 0 || urls.value[0] == '') {
		Message.error(i18n.global.t('domain.edit.domainConfiguration.fillDomain'))
	} else if (!isUrl(urls.value[0])) {
		Message.error(i18n.global.t('domain.edit.domainConfiguration.fillValidDomain'))
	} else {
		try {
			await initAiConfiguration({
				domain: domainTit.value,
				urls: urls.value,
			})
			globalStore.domainSource = domainTit.value
			waitAndCheckDomainStatusRef.value.open(domainTit.value, () => {
				updateHasBrandInfo(domainTit.value, 1)
				getDomainDetail(domainTit.value)
			})
		} catch (error) {
			console.warn(error)
		}
	}
}

/**
 * @description Update field names hasbrandinfo
 */
export async function updateHasBrandInfo(domain: string, hasbrandinfo: number) {
	try {
		await instance.post('/domains/update', {
			domain,
			hasbrandinfo,
		})
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Calculate based on units
 */
function calcBaseUnits(quota: number, unit: string) {
	switch (unit) {
		case 'KB':
			return quota * 1024
		case 'MB':
			return quota * 1024 * 1024
		case 'GB':
			return quota * 1024 * 1024 * 1024
		case 'TB':
			return quota * 1024 * 1024 * 1024 * 1024
		default:
			return quota
	}
}

/**
 * @description Sync domain to url
 */
export function syncToUrl(domainVal: string) {
	const { urls } = getEditDomainStoreData()
	const httpStr = urls.value[0].match(/http:\/\/?/g)
	const httpsStr = urls.value[0].match(/https:\/\/?/g)
	if (httpStr) {
		urls.value[0] = httpStr[0] + domainVal
	}

	if (httpsStr) {
		urls.value[0] = httpsStr[0] + domainVal
	}

	if (!httpStr && !httpsStr) {
		urls.value[0] = 'https://' + domainVal
	}
}

/**
 * @description Remove url
 */
export function removeUrl(index: number) {
	const { urls } = getEditDomainStoreData()

	urls.value.splice(index, 1)
}

/**
 * @description Reset all api status
 */
export function resetAllApiStatus() {
	const {
		hasGotAisettings,
		hasGotCompanyProfile,
		hasGotDomainConfiguration,
		hasGotFootersettings,
		hasGotProjectDetail,
		hasGotSitemap,
		hasGotStyling,
	} = getEditDomainStoreData()
	hasGotAisettings.value = false
	hasGotCompanyProfile.value = false
	hasGotDomainConfiguration.value = false
	hasGotFootersettings.value = false
	hasGotProjectDetail.value = false
	hasGotSitemap.value = false
	hasGotStyling.value = false
}

/**
 * @description Switch brand info
 */
export async function switchBrandInfo(value: boolean) {
	const { brandInfo, domainTit } = getEditDomainStoreData()
	try {
		await instance.post(
			'/askai/project/set_project_status',
			{ domain: domainTit.value, status: value },
			instanceOptions
		)
		await instance.post('/domains/update', {
			domain: domainTit.value,
			active: 1,
			hasbrandinfo: Number(value),
		})
	} catch (error) {
		brandInfo.value = !value
		console.warn(error)
	}
}
