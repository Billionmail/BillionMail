<template>
	<div
		ref="codeContainer"
		class="code-container"
		:class="{ 'with-line-numbers': showLineNumbers, 'word-wrap': wordWrap }"
		:style="{ height: height }"
		@scroll="onScroll">
		<!-- 虚拟滚动容器 -->
		<div
			v-if="shouldUseVirtualScroll"
			class="virtual-scroll-container"
			:style="{ height: totalHeight + 'px', minHeight: '100%' }">
			<!-- 行号容器 -->
			<div
				v-if="showLineNumbers"
				ref="lineNumbersContainer"
				class="line-numbers-container virtual"
				:style="{
					width: lineNumberWidth,
					transform: `translate3d(0, ${startOffset}px, 0)`,
					height: visibleHeight + 'px',
				}">
				<div
					v-for="(line, index) in visibleLines"
					:key="line.originalIndex"
					class="line-number"
					:class="{
						highlighted: highlightedLines.includes(line.lineNumber),
						'original-line': line.isOriginalLine,
					}"
					:style="{
						height: actualLineHeight + 'px',
						lineHeight: actualLineHeight + 'px',
					}">
					{{ line.isOriginalLine ? line.lineNumber : '' }}
				</div>
			</div>
			<!-- 代码内容容器 -->
			<div
				ref="codeContent"
				class="code-content virtual"
				:style="{
					marginLeft: showLineNumbers ? lineNumberWidth : '0',
					transform: `translate3d(0, ${startOffset}px, 0)`,
					height: visibleHeight + 'px',
				}">
				<div class="code-lines-container">
					<div
						v-for="(line, index) in visibleCodeLines"
						:key="visibleStartIndex + index"
						class="code-line"
						:class="{ 'highlighted-line': highlightedLines.includes(visibleStartIndex + index + 1) }"
						:style="{
							height: actualLineHeight + 'px',
							lineHeight: actualLineHeight + 'px',
						}"
						v-html="highlightLine(line)"></div>
				</div>
			</div>
		</div>

		<!-- 非虚拟滚动容器（优化后的逻辑） -->
		<template v-else>
			<!-- 优化的行号容器 -->
			<div
				v-if="showLineNumbers"
				ref="lineNumbersContainer"
				class="line-numbers-container non-virtual"
				:style="{ width: lineNumberWidth }">
				<div
					v-for="(line, index) in optimizedDisplayLines"
					:key="`line-${index}`"
					class="line-number"
					:class="{
						highlighted: highlightedLines.includes(getOriginalLineNumber(index)),
						'original-line': line.isOriginalLine,
					}"
					:style="{ minHeight: getMinLineHeight() + 'px' }">
					{{ line.isOriginalLine ? line.lineNumber : '' }}
				</div>
			</div>
			<!-- 优化的代码内容容器 -->
			<div
				ref="codeContent"
				class="code-content non-virtual"
				:style="{ marginLeft: showLineNumbers ? lineNumberWidth : '0' }">
				<pre
					ref="codePre"
					class="code-pre"
					:class="[`language-${language}`, { 'word-wrap': wordWrap }]">
					<code 
						ref="codeElement" 
						:class="`language-${language}`"
						v-html="highlightedCode"></code>
				</pre>
			</div>
		</template>
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
	// 新增虚拟滚动相关属性
	enableVirtualScroll?: boolean
	itemHeight?: number
	overscan?: number
	virtualScrollThreshold?: number
	// 新增：初始化滚动条位置选项
	scrollToBottom?: boolean
}

const props = withDefaults(defineProps<Props>(), {
	language: 'log',
	showLineNumbers: true,
	copyable: true,
	height: '100%',
	highlightedLines: () => [],
	wordWrap: true,
	trimWhitespace: true,
	// 虚拟滚动默认配置
	enableVirtualScroll: true,
	itemHeight: 21, // 每行高度（px）
	overscan: 5, // 预渲染行数
	virtualScrollThreshold: 200, // 超过多少行启用虚拟滚动
	// 默认滚动到底部
	scrollToBottom: false,
})

const codePre = ref<HTMLElement | null>(null)
const codeElement = ref<HTMLElement | null>(null)
const lineNumbersContainer = ref<HTMLElement | null>(null)
const codeContent = ref<HTMLElement | null>(null)
const codeContainer = ref<HTMLElement | null>(null)

// 虚拟滚动状态
const scrollTop = ref(0)
const containerHeight = ref(0)
const isScrolling = ref(false)

// 缓存相关
const lineHeightCache = ref<number | null>(null)
const wrappedLinesCache = ref<Map<string, number>>(new Map())
const highlightCache = ref<Map<string, string>>(new Map())

// 实际行高（响应式）
const actualLineHeight = ref(props.itemHeight)

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

// 是否应该启用虚拟滚动
const shouldUseVirtualScroll = computed(() => {
	// 如果显式设置为 false，则不启用
	if (props.enableVirtualScroll === false) {
		return false
	}
	// 如果行数超过阈值，则自动启用虚拟滚动
	return codeLines.value.length > props.virtualScrollThreshold
})

// 获取实际行高（优化版本，更准确的计算）
const getActualLineHeight = (): number => {
	if (lineHeightCache.value !== null) {
		return lineHeightCache.value
	}

	// 尝试从实际渲染的元素中获取行高
	if (shouldUseVirtualScroll.value && codeContainer.value) {
		// 创建一个临时的测量元素
		const measureElement = document.createElement('div')
		measureElement.style.cssText = `
			position: absolute;
			visibility: hidden;
			height: auto;
			width: auto;
			white-space: nowrap;
			font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
			font-size: 14px;
			line-height: 1.5;
			padding: 0;
			margin: 0;
		`
		measureElement.textContent = 'Ag'
		document.body.appendChild(measureElement)
		
		const measuredHeight = measureElement.offsetHeight
		document.body.removeChild(measureElement)
		
		if (measuredHeight > 0) {
			lineHeightCache.value = measuredHeight
			actualLineHeight.value = measuredHeight
			return measuredHeight
		}
	}

	// 如果有实际的代码元素，从中获取行高
	if (codePre.value) {
		const computedStyle = getComputedStyle(codePre.value)
		const lineHeight = parseFloat(computedStyle.lineHeight)
		if (!isNaN(lineHeight) && lineHeight > 0) {
			lineHeightCache.value = lineHeight
			actualLineHeight.value = lineHeight
			return lineHeight
		}
	}

	// 回退到配置的行高
	lineHeightCache.value = props.itemHeight
	actualLineHeight.value = props.itemHeight
	return props.itemHeight
}

// 获取最小行高（用于非虚拟滚动模式）
const getMinLineHeight = (): number => {
	return Math.max(getActualLineHeight(), 18) // 最小18px
}

// 优化的换行计算函数（使用缓存）
const calculateWrappedLines = (text: string): number => {
	if (!props.wordWrap || !codePre.value) return 1

	// 检查缓存
	const cacheKey = `${text}_${codePre.value.clientWidth}`
	if (wrappedLinesCache.value.has(cacheKey)) {
		return wrappedLinesCache.value.get(cacheKey)!
	}

	// 获取容器的实际宽度
	const containerWidth = codePre.value.clientWidth - 32 // 减去 padding
	if (containerWidth <= 0) {
		wrappedLinesCache.value.set(cacheKey, 1)
		return 1
	}

	// 简化的换行计算：基于字符数估算
	const avgCharWidth = 8 // 平均字符宽度（像素）
	const maxCharsPerLine = Math.floor(containerWidth / avgCharWidth)
	const wrappedLines = Math.max(1, Math.ceil(text.length / maxCharsPerLine))

	// 缓存结果
	wrappedLinesCache.value.set(cacheKey, wrappedLines)
	return wrappedLines
}

// 监听容器大小变化，重新计算换行
const resizeObserver = ref<ResizeObserver | null>(null)

// 强制重新计算的触发器
const forceRecalculate = ref(0)

// 优化的显示行计算（减少重复计算）
const optimizedDisplayLines = computed(() => {
	// 添加 forceRecalculate 作为依赖，确保容器大小变化时重新计算
	forceRecalculate.value

	if (!props.wordWrap) {
		// 不换行模式下，每行对应一个显示行
		return codeLines.value.map((_, index) => ({
			lineNumber: index + 1,
			isOriginalLine: true,
		}))
	}

	// 在自动换行模式下，使用优化的计算
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

// 兼容旧版本的 displayLines
const displayLines = computed(() => optimizedDisplayLines.value)

// 优化的代码高亮（使用缓存）
const highlightedCode = computed(() => {
	if (shouldUseVirtualScroll.value) {
		return processedCode.value // 虚拟滚动模式下不在这里高亮
	}

	const cacheKey = `${processedCode.value}_${props.language}`
	if (highlightCache.value.has(cacheKey)) {
		return highlightCache.value.get(cacheKey)!
	}

	try {
		const highlighted = Prism.highlight(
			processedCode.value,
			Prism.languages[props.language] || Prism.languages.log,
			props.language
		)
		highlightCache.value.set(cacheKey, highlighted)
		return highlighted
	} catch (error) {
		console.warn('代码高亮失败:', error)
		highlightCache.value.set(cacheKey, processedCode.value)
		return processedCode.value
	}
})

// 虚拟滚动相关计算 - 优化版本
const totalHeight = computed(() => {
	if (!shouldUseVirtualScroll.value) return 0
	return codeLines.value.length * actualLineHeight.value
})

const startIndex = computed(() => {
	if (!shouldUseVirtualScroll.value) return 0
	const index = Math.floor(scrollTop.value / actualLineHeight.value) - props.overscan
	return Math.max(0, index)
})

const endIndex = computed(() => {
	if (!shouldUseVirtualScroll.value) return 0
	const visibleCount = Math.ceil(containerHeight.value / actualLineHeight.value)
	const index = startIndex.value + visibleCount + props.overscan * 2
	return Math.min(codeLines.value.length - 1, index)
})

const startOffset = computed(() => {
	if (!shouldUseVirtualScroll.value) return 0
	return startIndex.value * actualLineHeight.value
})

const visibleHeight = computed(() => {
	if (!shouldUseVirtualScroll.value) return 0
	return (endIndex.value - startIndex.value + 1) * actualLineHeight.value
})

const visibleStartIndex = computed(() => {
	return startIndex.value
})

const visibleLines = computed(() => {
	if (!shouldUseVirtualScroll.value) return []
	const start = startIndex.value
	const end = endIndex.value + 1

	const result = []
	for (let i = start; i < end && i < codeLines.value.length; i++) {
		result.push({
			lineNumber: i + 1,
			isOriginalLine: true,
			originalIndex: i,
		})
	}
	return result
})

const visibleCodeLines = computed(() => {
	if (!shouldUseVirtualScroll.value) return []
	const start = startIndex.value
	const end = endIndex.value + 1
	return codeLines.value.slice(start, end)
})

// 高亮单行代码（虚拟滚动模式使用）
const highlightLine = (line: string): string => {
	const cacheKey = `line_${line}_${props.language}`
	if (highlightCache.value.has(cacheKey)) {
		return highlightCache.value.get(cacheKey)!
	}

	try {
		const highlighted = Prism.highlight(
			line,
			Prism.languages[props.language] || Prism.languages.log,
			props.language
		)
		highlightCache.value.set(cacheKey, highlighted)
		return highlighted
	} catch (error) {
		console.warn('代码高亮失败:', error)
		highlightCache.value.set(cacheKey, line)
		return line
	}
}

// 获取原始行号
const getOriginalLineNumber = (displayIndex: number): number => {
	return displayLines.value[displayIndex]?.lineNumber || 1
}

// 优化的滚动事件处理（使用节流和防抖结合）
let scrollTimer: number | null = null
let scrollEndTimer: number | null = null

const onScroll = () => {
	if (!codeContainer.value) return

	// 标记正在滚动
	isScrolling.value = true

	// 清除之前的定时器
	if (scrollTimer) {
		cancelAnimationFrame(scrollTimer)
	}
	if (scrollEndTimer) {
		clearTimeout(scrollEndTimer)
	}

	// 立即更新滚动位置（使用 RAF 节流）
	scrollTimer = requestAnimationFrame(() => {
		if (!codeContainer.value) return

		const newScrollTop = codeContainer.value.scrollTop
		
		// 只有当滚动位置真正改变时才更新
		if (Math.abs(newScrollTop - scrollTop.value) > 0.5) {
			scrollTop.value = newScrollTop
		}

		// 同步行号滚动（非虚拟滚动模式）
		if (!shouldUseVirtualScroll.value && lineNumbersContainer.value) {
			lineNumbersContainer.value.scrollTop = newScrollTop
		}
	})

	// 滚动结束检测
	scrollEndTimer = setTimeout(() => {
		isScrolling.value = false
		// 滚动结束后进行精确校准
		if (shouldUseVirtualScroll.value) {
			calibrateVirtualScroll()
		}
	}, 150)
}

// 更新容器高度和实际行高 - 优化版本
const updateContainerHeight = () => {
	if (!codeContainer.value) return

	const newHeight = codeContainer.value.clientHeight
	if (Math.abs(newHeight - containerHeight.value) > 1) {
		containerHeight.value = newHeight

		// 清除行高缓存，强制重新计算
		lineHeightCache.value = null
		
		// 重新获取实际行高
		nextTick(() => {
			getActualLineHeight()
			
			if (shouldUseVirtualScroll.value) {
				// 重新计算滚动位置
				onScroll()
			}
		})
	}
}

// 滚动到底部的方法 - 优化版本
const scrollToBottomMethod = () => {
	if (!codeContainer.value) return

	nextTick(() => {
		if (shouldUseVirtualScroll.value) {
			// 虚拟滚动模式：计算最大滚动位置
			const maxScrollTop = Math.max(0, totalHeight.value - containerHeight.value + 20)
			codeContainer.value!.scrollTop = maxScrollTop
			scrollTop.value = maxScrollTop
		} else {
			// 非虚拟滚动模式：直接滚动到底部
			codeContainer.value!.scrollTop = codeContainer.value!.scrollHeight
		}
	})
}

// 滚动到指定行
const scrollToLine = (lineNumber: number) => {
	if (!codeContainer.value || lineNumber < 1 || lineNumber > codeLines.value.length) return

	nextTick(() => {
		if (shouldUseVirtualScroll.value) {
			// 虚拟滚动模式：计算目标位置
			const targetScrollTop = (lineNumber - 1) * actualLineHeight.value
			codeContainer.value!.scrollTop = targetScrollTop
			scrollTop.value = targetScrollTop
		} else {
			// 非虚拟滚动模式：使用原生滚动
			const lineElement = codeContainer.value!.querySelector(`.line-number:nth-child(${lineNumber})`)
			if (lineElement) {
				lineElement.scrollIntoView({ behavior: 'smooth', block: 'center' })
			}
		}
	})
}

// 清除缓存的方法
const clearCaches = () => {
	wrappedLinesCache.value.clear()
	highlightCache.value.clear()
	lineHeightCache.value = null
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

// 校准虚拟滚动高度
const calibrateVirtualScroll = () => {
	if (!shouldUseVirtualScroll.value || !codeContainer.value || isScrolling.value) return

	nextTick(() => {
		// 强制重新计算所有虚拟滚动相关的值
		updateContainerHeight()

		// 确保行高是最新的
		getActualLineHeight()

		// 触发一次滚动事件以确保位置正确
		if (!isScrolling.value) {
			onScroll()
		}
	})
}

// 初始化滚动位置
const initializeScrollPosition = () => {
	if (props.scrollToBottom) {
		scrollToBottomMethod()
	}
}

// 在组件挂载后立即更新容器高度
onMounted(() => {
	// 延迟初始化，确保DOM完全渲染
	nextTick(() => {
		updateContainerHeight()
		getActualLineHeight()

		// 监听窗口大小变化
		window.addEventListener('resize', debounce(updateContainerHeight, 100))

		// 使用 ResizeObserver 监听容器大小变化
		if (codeContainer.value && ResizeObserver) {
			resizeObserver.value = new ResizeObserver(debounce(() => {
				clearCaches() // 清除缓存
				updateContainerHeight()
				forceRecalculate.value++
			}, 100))
			resizeObserver.value.observe(codeContainer.value)
		}

		// 初始化滚动位置
		setTimeout(() => {
			initializeScrollPosition()
		}, 200) // 延迟确保所有计算完成
	})
})

// 监听代码变化
watch(
	() => [processedCode.value, props.language, shouldUseVirtualScroll.value],
	() => {
		// 清除相关缓存
		highlightCache.value.clear()
		
		nextTick(() => {
			if (shouldUseVirtualScroll.value) {
				// 虚拟滚动模式下重新校准
				setTimeout(() => {
					calibrateVirtualScroll()
				}, 50)
			}

			// 如果启用了滚动到底部，在内容变化后重新滚动
			if (props.scrollToBottom) {
				setTimeout(() => {
					initializeScrollPosition()
				}, 100)
			}
		})
	},
	{ deep: true }
)

// 监听换行设置变化
watch(
	() => props.wordWrap,
	() => {
		// 清除换行缓存
		wrappedLinesCache.value.clear()
		forceRecalculate.value++
		
		// 重新校准虚拟滚动
		if (shouldUseVirtualScroll.value) {
			setTimeout(() => {
				calibrateVirtualScroll()
			}, 50)
		}
	}
)

// 监听行高变化
watch(
	() => props.itemHeight,
	() => {
		lineHeightCache.value = null
		actualLineHeight.value = props.itemHeight
		
		if (shouldUseVirtualScroll.value) {
			setTimeout(() => {
				calibrateVirtualScroll()
			}, 50)
		}
	}
)

// 组件卸载时清理
onUnmounted(() => {
	if (resizeObserver.value) {
		resizeObserver.value.disconnect()
	}
	window.removeEventListener('resize', updateContainerHeight)
	if (scrollTimer) {
		cancelAnimationFrame(scrollTimer)
	}
	if (scrollEndTimer) {
		clearTimeout(scrollEndTimer)
	}
	clearCaches()
})

// 暴露方法给父组件使用
defineExpose({
	scrollToBottom: scrollToBottomMethod,
	scrollToLine,
	clearCaches,
	calibrateVirtualScroll,
})

// 计算行号容器宽度
const lineNumberWidth = computed(() => {
	const maxLineNumber = codeLines.value.length
	const digits = maxLineNumber.toString().length
	// 基础宽度 + 每个数字的宽度 + 内边距
	const baseWidth = 1.5 // rem
	const digitWidth = 0.6 // rem per digit
	const padding = 1.5 // rem for padding
	return `${baseWidth + digits * digitWidth + padding}em`
})
</script>

<style lang="scss" scoped>
.code-container {
	position: relative;
	overflow: auto;
	border-radius: 4px;
	box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
	background: #2d2d2d;
	border: 1px solid #404040;

	&.word-wrap {
		.code-content {
			overflow: visible;
		}
	}
}

.virtual-scroll-container {
	position: relative;
	width: 100%;
	overflow: hidden;
	// 启用硬件加速
	transform: translateZ(0);
	will-change: scroll-position;

	&.word-wrap {
		.code-content {
			overflow: visible;
		}
	}
}

.code-content {
	position: relative;
	height: 100%;

	&.non-virtual {
		overflow: auto;
	}

	&.virtual {
		position: absolute;
		top: 0;
		left: 0;
		width: calc(100% - var(--line-number-width, 0px));
		overflow: visible;
		// 启用硬件加速
		will-change: transform;
		backface-visibility: hidden;
	}

	.word-wrap & {
		overflow: visible;
	}
}

.code-lines-container {
	font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
	font-size: 14px;
	line-height: 1.5;
	padding-left: 1rem;
	padding-right: 1rem;
}

.code-line {
	display: flex;
	align-items: center;
	white-space: pre;
	overflow: hidden;
	box-sizing: border-box;
	color: #fff;
	padding: 0;
	margin: 0;
	// 优化渲染性能
	contain: layout style paint;

	&:hover {
		background: rgba(255, 255, 255, 0.05);
	}

	&.highlighted-line {
		background: rgba(59, 130, 246, 0.2);
	}
}

.code-pre {
	display: flex;
	margin: 0;
	padding: 1rem;
	height: 100%;
	overflow: visible;
	background: transparent !important;
	font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
	font-size: 14px;
	line-height: 1.5;
	box-sizing: border-box;

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
	min-height: 100%;
	background-color: #1e1e1e;
	border-right: 1px solid #404040;
	text-align: right;
	padding: 1rem 0.75rem;
	box-sizing: border-box;
	user-select: none;
	font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
	font-size: 14px;
	line-height: 1.5;
	color: #666;
	z-index: 1;
	overflow: hidden;

	&.non-virtual {
		overflow-y: auto;
		scrollbar-width: none;
		-ms-overflow-style: none;

		&::-webkit-scrollbar {
			display: none;
		}
	}

	&.virtual {
		position: absolute;
		padding: 0;
		padding-right: 0.75rem;
		padding-left: 0.75rem;
		min-height: auto;
		top: 0;
		// 启用硬件加速
		will-change: transform;
		backface-visibility: hidden;
	}

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
	box-sizing: border-box;
	padding: 0;
	margin: 0;
	// 优化渲染性能
	contain: layout style paint;

	&.highlighted {
		background: #3b82f6;
		color: #fff;
		margin: 0 -0.75rem;
		padding: 0 0.75rem;
	}

	.virtual & {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		padding: 0;
		margin: 0;
		box-sizing: border-box;
	}
}

// 滚动条样式
.code-container::-webkit-scrollbar {
	width: 8px;
	height: 8px;
}

.code-container::-webkit-scrollbar-track {
	background: #1e1e1e;
}

.code-container::-webkit-scrollbar-thumb {
	background: #404040;
	border-radius: 4px;
}

.code-container::-webkit-scrollbar-thumb:hover {
	background: #555;
}

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
