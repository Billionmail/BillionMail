<template>
	<div class="flex items-center gap-16px w-full">
		<n-card class="flex-1">
			<pre>{{ value || '--' }}</pre>
		</n-card>
		<n-button @click="handleCopy">
			{{ $t('common.actions.copy') }}
		</n-button>
	</div>
</template>

<script lang="ts" setup>
import { useCopy } from '@/hooks/useCopy'

const { value } = defineProps({
	value: {
		type: String,
		default: '',
	},
})

const { copyText } = useCopy()

const handleCopy = async () => {
	await copyText(value)
}
</script>

<style lang="scss" scoped>
.n-card {
	--n-padding-top: 8px;
	--n-padding-left: 8px;
	--n-padding-right: 8px;
	--n-padding-bottom: 8px;
}

pre {
	line-height: 18px;
}
</style>
