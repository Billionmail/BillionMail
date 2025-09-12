<template>
	<bt-modal
		v-model:show="show"
		:title="$t('mailbox.form.exportTitle')"
		:width="480"
		@confirm="onConfirm">
		<bt-form class="pt-8px">
			<n-form-item :label="$t('mailbox.form.domain')">
				<domain-select v-model:value="domain"></domain-select>
			</n-form-item>
		</bt-form>
	</bt-modal>
</template>

<script lang="ts" setup>
import { exportMailbox } from '@/api/modules/mailbox'
import DomainSelect from './DomainSelect.vue'

const show = ref(false)

const domain = ref<string | null>(null)

const onConfirm = async () => {
	await exportMailbox({ domain: domain.value || '' })
}

const open = (val: string | null) => {
	domain.value = val || null
	show.value = true
}

defineExpose({
	open,
})
</script>

<style lang="scss" scoped></style>
