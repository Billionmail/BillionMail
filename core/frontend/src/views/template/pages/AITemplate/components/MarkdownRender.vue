<template>
	<div>
		<!-- When content is code -->
		<div v-if="languageTit" class="code-area">
			<div class="code-tool">
				<span>{{ languageTit }}</span>
				<div class="tools">
					<div class="tool-item" @click="copyContent">
						<i class="i-material-symbols:chrome-restore-rounded text-5"></i>
						<span>{{
							copied ? $t('template.ai.buttons.copied') : $t('template.ai.buttons.copy')
						}}</span>
					</div>
					<div class="tool-item" @click="viewCodeRender">
						<i class="i-mingcute:eye-2-fill text-5"></i>
						<span>{{ $t('template.ai.buttons.view') }}</span>
					</div>
					<div class="tool-item" @click="saveCodeChange(store)">
						<i class="i-ic:baseline-save text-5"></i>
						<span>{{ $t('template.ai.buttons.apply') }}</span>
					</div>
				</div>
			</div>
			<div v-html="codeHtml"></div>
		</div>

		<!-- When content is markdown -->
		<div v-else ref="codeRef" v-html="codeHtml"></div>
	</div>
</template>

<script setup lang="ts">
import markdownit from 'markdown-it'
import hljs from 'highlight.js'
import '../highlight.theme.css'
import { removeHtmlCodeBlockMarkers,removeSignCode,saveCodeChange } from '../controller'
import { TemplateStore } from '../dto'
import { useClipboard } from '@vueuse/core'
const { copy, copied } = useClipboard()
const store = inject<TemplateStore>('modelStore')!
const { currentChatRecordKey, previewCode } = store
const props = defineProps<{
	content: string
	chatRecordKey: string
}>()
const emits = defineEmits(['codeRender'])
const codeRef = ref()
const languageTit = ref('')
const codeHtml = ref('')

const md = markdownit({
	html: true,
	linkify: true,
	typographer: true,
	langPrefix: 'language-',
	highlight: function (str, lang): any {
		languageTit.value = lang
		if (lang && hljs.getLanguage(lang)) {
			try {
				return hljs.highlight(lang, str).value
			} catch {
				// console.warn(__)
			}
		}

		return md.utils.escapeHtml(str) // 使用额外的默认转义
	},
})

codeHtml.value = md.render(removeSignCode(props.content))
watch(
	() => props.content,
	val => {
		codeHtml.value = md.render(val)
		if (languageTit.value) {
			emits('codeRender', {
				code: props.content,
				key: props.chatRecordKey,
			})
		}
	},
	{immediate:true}
)

/**
 * @description Click to view code render
 */
function viewCodeRender() {
	currentChatRecordKey.value = props.chatRecordKey
	nextTick(() => (previewCode.value = removeHtmlCodeBlockMarkers(props.content)))
}

/**
 * @description Click to copy code
 */
function copyContent() {
	copy(props.content)
}
</script>

<style scoped lang="scss">
@use '@/styles/index' as base;
@use '../../../mixin.scss';

@mixin item-tool {
	@include base.row-flex-start;
	cursor: pointer;
	gap: 5px;
	padding: 5px 10px;
	align-items: center;
	font-size: 12px;
	border-radius: 3px;
	transition: 0.1s all ease-in-out;

	&:hover {
		background: var(--color-primary-1);
		color: #fff;
	}

	&:active {
		background: var(--color-primary-3);
	}
}

.code-area {
	.code-tool {
		@include base.row-flex;
		justify-content: space-between;
		align-items: center;
		height: 34px;
		background: var(--color-card-text-1);
		color: var(--color-bg-1);
		padding: 0 0 0 10px;

		.tools {
			@include base.row-flex-start;
			gap: 10px;

			.tool-item {
				height: 34px;
				@include item-tool();
				border-radius: 0;
			}
		}
	}

	:deep(pre) {
		background: #333;
		margin: 0;
		padding: 10px;
		font-size: 14px;
	}
}
</style>
