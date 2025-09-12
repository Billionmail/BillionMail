/**
 * @description Sitemap site url info
 */
export type SiteInfo = { title: string, uri_path: string, isSaved?: boolean }

/**
 * @description Profile detail knowledge base
 */
export type KnowledgeBase = {
    title: string
    content: string
    kid: string
    update_time: number
}