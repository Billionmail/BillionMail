import { defineStore } from 'pinia'
import { isObject } from '@/utils'
import { getLanguages, setLanguage as setLanguageApi } from '@/api/modules/public'

const PT_BR_LOCALE = 'pt-BR'
const FRONTEND_LOCALE_KEY = 'billionmail:frontend-locale'

interface LangResponse {
	current_language: string
	available_languages: Array<{ cn: string; name: string }>
}

export default defineStore('GlobalStore', () => {
	const domainSource = ref("")
	const lang = ref('en')

	const langList = ref<Array<{ cn: string; name: string }>>([])

	const isCollapse = ref(false)

	const temp_subject = ref("")

	const setCollapse = () => {
		isCollapse.value = !isCollapse.value
	}

	const getLang = async () => {
		if (langList.value.length > 0) return

		const res = await getLanguages()
		if (isObject<LangResponse>(res)) {
			lang.value = localStorage.getItem(FRONTEND_LOCALE_KEY) === PT_BR_LOCALE
                ? PT_BR_LOCALE
                : res.current_language
            langList.value = [
                ...res.available_languages.filter(item => item.name !== PT_BR_LOCALE),
                { cn: 'Português (Brasil)', name: PT_BR_LOCALE },
            ]
		}
	}

	const setLang = async (language: string) => {
        if (language === PT_BR_LOCALE) {
            localStorage.setItem(FRONTEND_LOCALE_KEY, PT_BR_LOCALE)
            lang.value = PT_BR_LOCALE
            return
        }

        await setLanguageApi({ language })
        localStorage.removeItem(FRONTEND_LOCALE_KEY)
        lang.value = language
    }

	return {
		domainSource,
		lang,
		langList,
		isCollapse,
		temp_subject,
		getLang,
		setLang,
		setCollapse,
	}
}, {
	persist: [
		{
			pick: ["domainSource"],
			storage: localStorage
		}
	]
})
