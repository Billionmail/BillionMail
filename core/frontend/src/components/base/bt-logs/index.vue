<template>
	<div
		class="code-container"
		:class="{ 'with-line-numbers': showLineNumbers, 'word-wrap': wordWrap }">
		<div v-if="showLineNumbers" ref="lineNumbersContainer" class="line-numbers-container">
			<div
				v-for="(line, index) in displayLines"
				:key="index"
				class="line-number"
				:class="{
					highlighted: highlightedLines.includes(getOriginalLineNumber(index)),
					'original-line': line.isOriginalLine,
				}">
				{{ line.isOriginalLine ? line.lineNumber : '' }}
			</div>
		</div>
		<div ref="codeContent" class="code-content">
			<pre
				ref="codePre"
				class="code-pre"
				:class="[`language-${language}`, { 'word-wrap': wordWrap }]"
				:style="{ height: height }"
				@scroll="onScroll">
				<code ref="codeElement" :class="`language-${language}`">{{ processedCode }}</code>
			</pre>
		</div>
	</div>
</template>

<script lang="ts" setup>
import Prism from 'prismjs'
import 'prismjs/components/prism-log'
import 'prismjs/themes/prism-tomorrow.css'

// 扩展语言定义类型
type Language = 'log'

interface Props {
	code: string
	language?: Language
	showLineNumbers?: boolean
	copyable?: boolean
	height?: string
	highlightedLines?: number[]
	wordWrap?: boolean
	trimWhitespace?: boolean
}

const props = withDefaults(defineProps<Props>(), {
	language: 'log',
	showLineNumbers: true,
	copyable: true,
	height: '100%',
	highlightedLines: () => [],
	wordWrap: true,
	trimWhitespace: true,
})

const codePre = ref<HTMLElement | null>(null)
const codeElement = ref<HTMLElement | null>(null)
const lineNumbersContainer = ref<HTMLElement | null>(null)
const codeContent = ref<HTMLElement | null>(null)

// 处理后的代码内容
const processedCode = computed(() => {
	let result = props.code

	// 清除整体前后空格
	if (props.trimWhitespace) {
		result = result.trim()
	}

	return result
})

// 计算属性：将代码按行分割
const codeLines = computed(() => processedCode.value.split('\n'))

// 计算显示的行号（包括换行后的虚拟行）
const displayLines = computed(() => {
	if (!props.wordWrap) {
		return codeLines.value.map((_, index) => ({
			lineNumber: index + 1,
			isOriginalLine: true,
		}))
	}

	// 在自动换行模式下，需要计算每行实际占用的显示行数
	const result: Array<{ lineNumber: number; isOriginalLine: boolean }> = []

	codeLines.value.forEach((line, index) => {
		const wrappedLineCount = calculateWrappedLines(line)

		// 第一行显示行号
		result.push({
			lineNumber: index + 1,
			isOriginalLine: true,
		})

		// 如果有换行，添加空的行号占位
		for (let i = 1; i < wrappedLineCount; i++) {
			result.push({
				lineNumber: index + 1,
				isOriginalLine: false,
			})
		}
	})

	return result
})

// 计算单行文本在当前容器宽度下会换成几行
const calculateWrappedLines = (text: string): number => {
	if (!codePre.value || !props.wordWrap) return 1

	// 获取容器的实际宽度
	const containerWidth = codePre.value.clientWidth - 32 // 减去 padding
	if (containerWidth <= 0) return 1

	// 创建临时元素来测量文本宽度
	const tempElement = document.createElement('span')
	tempElement.style.font = getComputedStyle(codePre.value).font
	tempElement.style.visibility = 'hidden'
	tempElement.style.position = 'absolute'
	tempElement.style.whiteSpace = 'nowrap'
	document.body.appendChild(tempElement)

	tempElement.textContent = text
	const textWidth = tempElement.offsetWidth
	document.body.removeChild(tempElement)

	return Math.max(1, Math.ceil(textWidth / containerWidth))
}

// 获取原始行号
const getOriginalLineNumber = (displayIndex: number): number => {
	return displayLines.value[displayIndex]?.lineNumber || 1
}

// 同步滚动
const onScroll = () => {
	if (lineNumbersContainer.value && codePre.value) {
		lineNumbersContainer.value.scrollTop = codePre.value.scrollTop
	}
}

// 监听容器大小变化，重新计算换行
const resizeObserver = ref<ResizeObserver | null>(null)

// 高亮代码函数
const highlightCode = () => {
	if (codeElement.value) {
		try {
			Prism.highlightElement(codeElement.value)
		} catch (error) {
			console.warn('代码高亮失败:', error)
		}
	}
}

// 防抖函数
const debounce = (func: Function, wait: number) => {
	let timeout: number
	return function executedFunction(...args: any[]) {
		const later = () => {
			clearTimeout(timeout)
			func(...args)
		}
		clearTimeout(timeout)
		timeout = setTimeout(later, wait)
	}
}

// 防抖的高亮函数
const debouncedHighlight = debounce(highlightCode, 100)

// 初始化和更新时高亮代码
onMounted(() => {
	nextTick(() => {
		highlightCode()

		// 设置 ResizeObserver 来监听容器大小变化
		if (codePre.value) {
			resizeObserver.value = new ResizeObserver(() => {
				// 触发重新计算
				nextTick(() => {
					// 强制重新计算 displayLines
				})
			})
			resizeObserver.value.observe(codePre.value)
		}
	})
})

onUnmounted(() => {
	if (resizeObserver.value) {
		resizeObserver.value.disconnect()
	}
})

// 监听代码变化
watch(
	() => [processedCode.value, props.language],
	() => {
		nextTick(() => {
			debouncedHighlight()
		})
	},
	{ deep: true }
)
</script>

<style lang="scss" scoped>
.code-container {
	position: relative;
	overflow: hidden;
	border-radius: 4px;
	box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
	background: #2d2d2d;
	border: 1px solid #404040;

	&.with-line-numbers {
		.code-content {
			margin-left: 3rem;
		}
	}

	&.word-wrap {
		.code-content {
			overflow: visible;
		}
	}
}

.code-header {
	display: flex;
	justify-content: space-between;
	align-items: center;
	padding: 0.75rem 1rem;
	background: #1e1e1e;
	border-bottom: 1px solid #404040;

	.code-title {
		font-size: 0.875rem;
		color: #e0e0e0;
		font-weight: 500;
	}

	.code-actions {
		display: flex;
		gap: 0.5rem;
	}
}

.copy-btn {
	display: flex;
	align-items: center;
	justify-content: center;
	width: 32px;
	height: 32px;
	border: none;
	background: transparent;
	color: #888;
	cursor: pointer;
	border-radius: 4px;
	transition: all 0.2s ease;

	&:hover {
		background: #404040;
		color: #e0e0e0;
	}

	&.copied {
		color: #4ade80;
	}
}

.code-content {
	position: relative;
	overflow: auto;

	.word-wrap & {
		overflow: visible;
	}
}

.code-pre {
	display: flex;
	margin: 0;
	padding: 1rem;
	overflow-x: auto;
	background: transparent !important;
	font-family: 'Fira Code', Consolas, Monaco, 'Andale Mono', monospace;
	font-size: 0.875rem;
	line-height: 1.5;

	&.word-wrap {
		overflow-x: visible;
		overflow-y: visible;
		white-space: pre-wrap;
		word-wrap: break-word;
		word-break: break-all;
	}

	code {
		flex: 1;
		background: transparent !important;
		padding: 0 !important;
		border-radius: 0 !important;

		.word-wrap & {
			white-space: pre-wrap;
			word-wrap: break-word;
			word-break: break-all;
		}
	}
}

.line-numbers-container {
	position: absolute;
	top: 0;
	left: 0;
	height: 100%;
	width: 3rem;
	background-color: #1e1e1e;
	border-right: 1px solid #404040;
	text-align: right;
	padding: 1rem 0.75rem;
	box-sizing: border-box;
	user-select: none;
	font-family: 'Fira Code', Consolas, Monaco, 'Andale Mono', monospace;
	font-size: 0.875rem;
	color: #666;
	z-index: 1;
	overflow: hidden;

	.word-wrap & {
		overflow-y: auto;
		scrollbar-width: none;
		-ms-overflow-style: none;

		&::-webkit-scrollbar {
			display: none;
		}
	}
}

.line-number {
	display: block;
	line-height: 1.5;
	min-height: 1.3125rem; // 21px (1.5 * 14px)
	height: 1.3125rem;

	&.highlighted {
		background: #3b82f6;
		color: #fff;
		margin: 0 -0.75rem;
		padding: 0 0.75rem;
	}

	.word-wrap & {
		height: 1.3125rem;
		line-height: 1.5;
	}
}

// 滚动条样式
.code-pre::-webkit-scrollbar {
	height: 8px;
}

.code-pre::-webkit-scrollbar-track {
	background: #1e1e1e;
}

.code-pre::-webkit-scrollbar-thumb {
	background: #404040;
	border-radius: 4px;
}

.code-pre::-webkit-scrollbar-thumb:hover {
	background: #555;
}
</style>
