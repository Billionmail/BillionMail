import { getEditDomainStoreData } from '../store'
import { instance } from '@/api'
import { instanceOptions } from './companyProfile.controller'
import { KnowledgeBase } from '../dto'
/**
 * @description Get project detail
 */
export async function getProjectDetail(domainStr: string) {
	const {
		project_name,
		primary_logo,
		favicon,
		industry,
		description,
		secondary_logo,
		hasGotProjectDetail,
		knowledge_base,
	} = getEditDomainStoreData()
	if (hasGotProjectDetail.value) return
	try {
		const res = (await instance.post('/askai/project/get_base_info', {
			domain: domainStr,
		})) as Record<string, any>
		project_name.value = res.project_name
		primary_logo.value = res.primary_logo
		favicon.value = res.favicon
		industry.value = res.industry
		description.value = res.description
		secondary_logo.value = res.secondary_logo
		knowledge_base.value = res.knowledge_base
		hasGotProjectDetail.value = true
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Update project detail
 */
export async function updateProjectDetail(domainStr: string) {
	const { project_name, primary_logo, favicon, industry, description, secondary_logo } =
		getEditDomainStoreData()
	try {
		await instance.post(
			'/askai/project/modify_base_info',
			{
				domain: domainStr,
				project_name: project_name.value,
				primary_logo: primary_logo.value,
				favicon: favicon.value,
				industry: industry.value,
				description: description.value,
				secondary_logo: secondary_logo.value,
			},
			instanceOptions
		)
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Create knowledge base
 */
export async function createKnowledgeBase(domain: string) {
	try {
		const { knowledgeTitle, knowledgeContent, hasGotProjectDetail } = getEditDomainStoreData()
		;(await instance.post(
			'/askai/project/create_knowledge_base_file',
			{
				domain,
				title: knowledgeTitle.value,
				content: knowledgeContent.value,
			},
			instanceOptions
		)) as Record<string, any>
		hasGotProjectDetail.value = false
		await getProjectDetail(domain)
		closeKnowledgeModal()
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Update knowledge base
 */
export async function updateKnowledgeBase(domain: string) {
	const { activeKnowledge, hasGotProjectDetail, knowledgeTitle, knowledgeContent } =
		getEditDomainStoreData()
	try {
		await instance.post('/askai/project/modify_knowledge_base_file', {
			domain,
			title: knowledgeTitle.value,
			content: knowledgeContent.value,
			kid: activeKnowledge.value.kid,
		})
		hasGotProjectDetail.value = false
		await getProjectDetail(domain)
		closeKnowledgeModal()
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Close knowledge modal
 */
export function closeKnowledgeModal() {
	const { knowledgeContent, knowledgeTitle, knowledgeModalShow, isEditKnowledge } =
		getEditDomainStoreData()
	knowledgeContent.value = ''
	knowledgeTitle.value = ''
	knowledgeModalShow.value = false
	isEditKnowledge.value = false
}

/**
 * @description Open edit knowledge modal
 */
export function openEditKnowledge(knowledge: KnowledgeBase) {
	const { knowledgeTitle, knowledgeContent, knowledgeModalShow, activeKnowledge, isEditKnowledge } =
		getEditDomainStoreData()

	activeKnowledge.value = knowledge
	knowledgeTitle.value = knowledge.title
	knowledgeContent.value = knowledge.content
	knowledgeModalShow.value = true
	isEditKnowledge.value = true
}

/**
 * @description Delete knowledge base
 */
export async function deleteKnowledgeBase(domain: string, knowledge: KnowledgeBase) {
	const { hasGotProjectDetail } = getEditDomainStoreData()
	try {
		await instance.post(
			'/askai/project/remove_knowledge_base_file',
			{ domain, kid: knowledge.kid },
			instanceOptions
		)
		hasGotProjectDetail.value = false
		getProjectDetail(domain)
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Preview knowledge base content
 */
export function previewKnowledgeBaseContent(knowledge_base: KnowledgeBase) {
	const { knowledge_base_content, knowledgeBasePreview, knowledgeBasePreviewTit } =
		getEditDomainStoreData()
	knowledgeBasePreview.value = true
	knowledge_base_content.value = knowledge_base.content
	knowledgeBasePreviewTit.value = knowledge_base.title
}

/**
 * @description Upload image
 */
export async function uploadImage(
	domain: string,
	image: string,
	filename: string,
	alt_text: string,
	image_tag: string
) {
	try {
		await instance.post(
			'/askai/project/upload_image',
			{
				domain,
				image,
				filename,
				alt_text,
				image_tag,
			},
			instanceOptions
		)
		// console.log(res)
	} catch (error) {
		console.warn(error)
		return ''
	}
}
