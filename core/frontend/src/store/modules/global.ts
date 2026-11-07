import { defineStore } from 'pinia'
import { useMediaQuery } from '@vueuse/core'
import { isObject } from '@/utils'
import { getLanguages, setLanguage as setLanguageApi } from '@/api/modules/public'

interface LangResponse {
	current_language: string
	available_languages: Array<{ cn: string; name: string }>
}

export default defineStore('GlobalStore', () => {
	const domainSource = ref("")
	const lang = ref('en')

	const langList = ref<Array<{ cn: string; name: string }>>([])

	const isCollapse = ref(false)

	// Below this width the sidebar behaves as an overlay drawer instead of
	// a permanent column (see Sidebar.vue / layout/index.vue).
	const isMobile = useMediaQuery('(max-width: 768px)')

	// Whether the mobile drawer is currently open. Kept separate from
	// isCollapse because on desktop "collapsed" still shows an icon rail,
	// while on mobile the sidebar is either fully open or fully hidden.
	const mobileMenuOpen = ref(false)

	const temp_subject = ref("")

	const setCollapse = () => {
		isCollapse.value = !isCollapse.value
	}

	// Single entry point for the header's hamburger button so it doesn't
	// need to know whether it's driving the desktop rail or the mobile drawer.
	const toggleSidebar = () => {
		if (isMobile.value) {
			mobileMenuOpen.value = !mobileMenuOpen.value
		} else {
			setCollapse()
		}
	}

	const closeMobileMenu = () => {
		mobileMenuOpen.value = false
	}

	const getLang = async () => {
		if (langList.value.length > 0) return

		const res = await getLanguages()
		if (isObject<LangResponse>(res)) {
			lang.value = res.current_language
			langList.value = res.available_languages
		}
	}

	const setLang = async (language: string) => {
		await setLanguageApi({ language })
	}

	return {
		domainSource,
		lang,
		langList,
		isCollapse,
		isMobile,
		mobileMenuOpen,
		temp_subject,
		getLang,
		setLang,
		setCollapse,
		toggleSidebar,
		closeMobileMenu,
	}
}, {
	persist: [
		{
			pick: ["domainSource"],
			storage: localStorage
		}
	]
})
