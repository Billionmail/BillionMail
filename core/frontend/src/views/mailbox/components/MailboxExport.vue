<template>
	<bt-modal
		v-model:show="show"
		:title="$t('mailbox.form.exportTitle')"
		:width="480"
		@confirm="onConfirm">
		<bt-form class="pt-8px">
			<n-form-item :label="$t('mailbox.form.domain')">
				<domain-select v-model:value="form.domain"></domain-select>
			</n-form-item>
			<n-form-item label="Format">
				<n-select v-model:value="form.format" :options="formatOptions"></n-select>
			</n-form-item>
		</bt-form>
	</bt-modal>
</template>

<script lang="ts" setup>
import { exportMailbox } from '@/api/modules/mailbox'
import DomainSelect from './DomainSelect.vue'

const show = ref(false)

const form = reactive({
	domain: null as string | null,
	format: 'csv',
})

const formatOptions = [
	{ label: 'CSV', value: 'csv' },
	{ label: 'TXT', value: 'txt' },
]

const onConfirm = async () => {
	await exportMailbox({ domain: form.domain || '', file_type: form.format })
}

const open = (val: string | null) => {
	form.domain = val || null
	form.format = 'csv'
	show.value = true
}

defineExpose({
	open,
})
</script>

<style lang="scss" scoped></style>
