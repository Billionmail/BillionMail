<template>
	<div class="flex items-center gap-16px w-full">
		<div class="markdown-body flex-1 w-0" v-html="result"></div>
		<n-button @click="handleCopy">{{ $t('common.actions.copy') }}</n-button>
	</div>
</template>

<script lang="ts" setup>
import { marked } from 'marked'
import hljs from 'highlight.js'
import 'highlight.js/styles/github.css'
import 'github-markdown-css'
import { useCopy } from '@/hooks/useCopy'

const { code, language } = defineProps({
	code: {
		type: String,
		default: '',
	},
	language: {
		type: String,
		default: 'shell',
	},
})

const content = computed(() => {
	return `\`\`\`${language}
${code}
\`\`\``
})

const result = computed(() => {
	return marked.parse(content.value)
})

const { copyText } = useCopy()

const handleCopy = () => {
	copyText(code)
}

// 创建自定义扩展
const highlightExtension = {
	name: 'highlight',
	level: 'block',
	start(src: string) {
		return src.match(/^```/)?.index
	},
	tokenizer(src: string) {
		const rule = /^```([^\n]*?)\n([\s\S]*?)\n```/
		const match = rule.exec(src)
		if (match) {
			return {
				type: 'highlight',
				raw: match[0],
				lang: match[1].trim(),
				code: match[2],
			}
		}
	},
	renderer(token: any) {
		const { lang, code } = token
		if (lang && hljs.getLanguage(lang)) {
			const highlighted = hljs.highlight(code, { language: lang }).value
			return `<pre><code class="hljs language-${lang}">${highlighted}</code></pre>`
		}
		return `<pre><code>${code}</code></pre>`
	},
}

// 使用扩展
marked.use({ extensions: [highlightExtension] })
</script>

<style lang="scss" scoped></style>
