import { createI18n } from 'vue-i18n'
import en from './lang/en.json'
import zh from './lang/zh.json'
import ja from './lang/ja.json'
import ptBR from './lang/pt-BR.json'

const i18n = createI18n({
	legacy: false,
	globalInjection: true,
	locale: 'en',
	fallbackLocale: 'en',
	messages: {
		en,
		zh,
		ja,
		'pt-BR': ptBR,
	},
})

// 提供切换语言的方法
export const setLanguage = (locale: string) => {
	i18n.global.locale.value = locale as 'en' | 'zh' | 'ja' | 'pt-BR'
}

export default i18n

export { i18n }
