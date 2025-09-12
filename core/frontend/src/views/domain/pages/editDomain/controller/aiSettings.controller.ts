/**
 * @description Get ai settings info
 */
import { instance } from "@/api";
import { instanceOptions } from "./companyProfile.controller";
import { getEditDomainStoreData } from "../store";
/**
 * @description Get ai settings info
 */
export async function getAisettingsInfo(domain: string) {
    const { prompt, hasGotAisettings } = getEditDomainStoreData()
    if (hasGotAisettings.value) return
    try {
        const res = await instance.post("/askai/project/get_prompt", { domain }) as Record<string, string>
        prompt.value = res.prompt
        hasGotAisettings.value = true
    } catch (error) {
        console.warn(error)
    }
}

/**
 * @description Update ai settings info
 */
export async function updateAiSettingsInfo(domain: string) {
    const { prompt } = getEditDomainStoreData()
    try {
        const res = await instance.post("/askai/project/modify_prompt", {
            domain,
            prompt: prompt.value
        }, instanceOptions) as Record<string, string>
        prompt.value = res.prompt
    } catch (error) {
        console.warn(error)
    }
}