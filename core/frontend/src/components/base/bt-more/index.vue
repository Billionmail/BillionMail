<template>
	<div class="flex items-center mb-20px cursor-pointer" @click="onToggle">
		<!-- <bt-icon
				name="base-arrow-right"
				size="15"
				:style="{
					transform: `rotate(${show ? '90' : '0'}deg)`,
					transition: 'transform 0.3s',
				}">
			</bt-icon> -->
		<n-icon
			size="16"
			:style="{
				transform: `rotate(${show ? '90' : '0'}deg)`,
				transition: 'transform 0.3s',
			}">
			<ChevronRightIcon />
		</n-icon>
		<div class="ml-8px text-13px text-primary">
			<slot name="title"></slot>
			{{ showTitle ? '' : title }}
		</div>
	</div>
	<n-collapse-transition :show="show">
		<slot></slot>
	</n-collapse-transition>
</template>

<script lang="ts" setup>
import { ChevronRightIcon } from 'naive-ui/es/_internal/icons'

defineProps({
	title: {
		type: String,
		default: '',
	},
})

const show = defineModel<boolean>('show', {
	default: false,
})

const onToggle = () => {
	show.value = !show.value
}

const showTitle = !!useSlots().title
</script>
