import { instance } from "@/api";
import { getEditDomainStoreData } from "../store";
export const instanceOptions = {
    fetchOptions: {
        loading: 'Loading... Please wait.',
        successMessage: true,
    }
}
/**
 * @description Get company profile
 * 
 * @param { string }  domain 
 */
export async function getCompanuyProfile(domain: string) {
    const {
        legal_company_name,
        web_site,
        company_profile,
        email,
        phone,
        support_url,
        hasGotCompanyProfile
    } = getEditDomainStoreData()
    if (hasGotCompanyProfile.value) return
    try {
        const res = await instance.post("/askai/project/get_company_profile", { domain } ) as Record<string, any>
        legal_company_name.value = res.legal_company_name
        web_site.value = res.web_site
        company_profile.value = res.company_profile
        email.value = res.email
        phone.value = res.phone
        support_url.value = res.support_url

        hasGotCompanyProfile.value = true
    } catch (error) {
        console.warn(error)
    }
}

/**
 * @description Update company profile
 */
export async function updateCompanyProfile(domain: string) {
    const {
        legal_company_name,
        web_site,
        company_profile,
        email,
        phone,
        support_url,
    } = getEditDomainStoreData()
    try {
        await instance.post("/askai/project/modify_company_profile", {
            domain,
            legal_company_name: legal_company_name.value,
            web_site: web_site.value,
            company_profile: company_profile.value,
            email: email.value,
            phone: phone.value,
            support_url: support_url.value,
        }, instanceOptions) as Record<string, any>
    } catch (error) {
        console.warn(error)
    }
}

