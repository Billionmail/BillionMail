import { instance } from "@/api";
import { instanceOptions } from "./companyProfile.controller";
import { getEditDomainStoreData } from "../store";
/***
 * @description Get footer settings info
 * 
 * @param { string } domain
 */
export async function getFootersettingsInfo(domain: string) {
    const {
        copyright_text,
        disclaimer,
        hasGotFootersettings
    } = getEditDomainStoreData()
    if (hasGotFootersettings.value) return
    try {
        const res = await instance.post("/askai/project/get_footer", { domain }) as Record<string, string>
        copyright_text.value = res.copyright_text
        disclaimer.value = res.disclaimer
        hasGotFootersettings.value = true
    } catch (error) {
        console.warn(error)
    }
}

/**
 * @description Update footer settings info
 * 
 */
export async function updateFooterSettingsInfo(domain: string) {
    const {
        copyright_text,
        disclaimer
    } = getEditDomainStoreData()
    try {
        await instance.post("/askai/project/modify_footer", {
            domain,
            copyright_text: copyright_text.value,
            disclaimer: disclaimer.value
        }, instanceOptions) as Record<string, string>
    } catch (error) {
        console.warn(error)
    }
}