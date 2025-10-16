import { instance } from '@/api'
import { getEditDomainStoreData } from '../store'
// import { instanceOptions } from "./companyProfile.controller"
/**
 * @description Update typography info
 */
export async function updateTypography(domain: string) {
	const { heading_font, body_font } = getEditDomainStoreData()
	try {
		await instance.post('/askai/project/modify_style_config', {
			domain,
			heading_font: heading_font.value,
			body_font: body_font.value,
		})
	} catch (error) {
		console.warn(error)
	}
}
