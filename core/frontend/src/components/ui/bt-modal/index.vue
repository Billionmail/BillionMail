<template>
	<n-modal
		v-model:show="show"
		preset="dialog"
		:z-index="zIndex"
		:draggable="true"
		:auto-focus="false"
		:show-icon="false"
		:mask-closable="false"
		:internal-appear="true"
		:internal-dialog="true"
		:transform-origin="transformOrigin"
		:style="{ width: formatLength(width) }"
		@after-leave="onAfterLeave">
		<template #header>{{ title }}</template>
		<div :style="{ maxHeight: maxScrollHeight, overflow: 'auto' }">
			<slot></slot>
		</div>
		<template v-if="footer" #action>
			<div class="flex justify-between flex-1">
				<div>
					<slot name="footer-left"></slot>
				</div>
				<div class="flex gap-12px">
					<n-button secondary @click="onCancel">
						{{ $t('common.actions.cancel') }}
					</n-button>
					<n-button :type="confirmType" @click="onConfirm">
						{{ confirmText || $t('common.actions.confirm') }}
					</n-button>
				</div>
			</div>
		</template>
	</n-modal>
</template>

<script lang="ts" setup>
import { useWindowSize } from '@vueuse/core'
import { formatLength } from 'naive-ui/es/_utils'
import { Type } from 'naive-ui/es/button/src/interface'

const props = defineProps({
	zIndex: Number,
	onAfterLeave: Function as PropType<() => void>,
	title: {
		type: String,
		default: '',
	},
	width: {
		type: [String, Number],
		default: 'auto',
	},
	minHeight: {
		type: [Number, String],
		default: 'auto',
	},
	footer: {
		type: Boolean,
		default: true,
	},
	transformOrigin: {
		type: String as PropType<'mouse' | 'center'>,
		default: 'center',
	},
	confirmText: {
		type: String,
		default: '',
	},
	confirmType: {
		type: String as PropType<Type>,
		default: 'primary',
	},
	onCancel: {
		type: Function as PropType<() => unknown>,
		default: () => true,
	},
	onConfirm: {
		type: Function as PropType<() => void | boolean | Promise<unknown>>,
		default: () => true,
	},
})

const show = defineModel<boolean>('show')

// Window height
const { height } = useWindowSize()

// Maximum scroll height
const maxScrollHeight = computed(() => {
	if (height.value) return `${height.value - 32}px`
	return 'auto'
})

const closeModal = () => {
	show.value = false
}

const onCancel = () => {
	const result = props.onCancel()
	if (result === false) return
	closeModal()
}

const onConfirm = () => {
	void Promise.resolve(props.onConfirm()).then(value => {
		if (value === false) return
		closeModal()
	})
}

const onAfterLeave = () => {
	props.onAfterLeave?.()
}
</script>
