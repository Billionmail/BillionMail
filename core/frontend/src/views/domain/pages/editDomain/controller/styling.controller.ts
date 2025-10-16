import { instance } from "@/api";
import { getEditDomainStoreData } from "../store";
import { instanceOptions } from "./companyProfile.controller"
/**
 * @description Get styling info
 * 
 * @param { string } domain
 */
export async function getStylingInfo(domain: string) {
    const {
        accent_color,
        text_color,
        page_background,
        container_background,
        link_social_color,
        link_footer_color,
        heading_font,
        body_font,
        hasGotStyling
    } = getEditDomainStoreData()
    if (hasGotStyling.value) return
    try {
        const res = await instance.post("/askai/project/get_style_config", { domain }) as Record<string, any>
        accent_color.value = res.accent_color
        text_color.value = res.text_color
        page_background.value = res.page_background
        container_background.value = res.container_background
        link_social_color.value = res.link_social_color
        link_footer_color.value = res.link_footer_color
        heading_font.value = res.heading_font
        body_font.value = res.body_font
        hasGotStyling.value = true
    } catch (error) {
        console.warn(error)
    }
}

/**
 * @description Update styling info
 */
export async function updateStylingInfo(domain: string) {
    const {
        accent_color,
        text_color,
        page_background,
        container_background,
        link_social_color,
        link_footer_color,
        heading_font,
        body_font,
    } = getEditDomainStoreData()
    try {
        await instance.post("/askai/project/modify_style_config", {
            domain,
            accent_color: accent_color.value,
            text_color: text_color.value,
            page_background: page_background.value,
            container_background: container_background.value,
            link_social_color:link_social_color.value,
            link_footer_color:link_footer_color.value,
            heading_font:heading_font.value,
            body_font:body_font.value
        }, instanceOptions) as Record<string, any>
    } catch (error) {
        console.warn(error)
    }
}