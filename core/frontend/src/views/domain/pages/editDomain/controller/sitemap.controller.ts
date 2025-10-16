import { instance } from "@/api";
import { instanceOptions } from "./companyProfile.controller";
import { getEditDomainStoreData } from "../store";
import { SiteInfo } from "../dto";
/**
 * @description Get Sitemap info
 * 
 * @param { string } domain
 */
export async function getSitemapInfo(domain: string) {
    const { sitemap, hasGotSitemap } = getEditDomainStoreData()
    if (hasGotSitemap.value) return
    try {
        const res = await instance.post("/askai/project/get_sitemap", { domain }) as SiteInfo[]
        sitemap.value = res.length == 0 ? [{ title: "", uri_path: "" }] : res.map(item => {
            item.isSaved = true
            return item
        })
        hasGotSitemap.value = true
    } catch (error) {
        console.warn(error)
    }
}

/**
 * @description Add sitemap url
 */
export async function addSitemapInfo(domain: string, title: string, uri_path: string) {
    try {
        await instance.post("/askai/project/add_sitemap_node", { domain, title, uri_path }, instanceOptions)
    } catch (error) {
        console.warn(error)
    }
}

/**
 * @description Remove sitemap url
 */
export async function removeSiteMapInfo(domain: string, uri_path: string) {
    try {
        await instance.post("/askai/project/remove_sitemap_node", { domain, uri_path }, instanceOptions)
    } catch (error) {
        console.warn(error)
    }
}