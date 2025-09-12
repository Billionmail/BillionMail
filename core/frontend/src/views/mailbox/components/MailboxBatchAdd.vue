<template>
	<bt-modal
		v-model:show="show"
		:title="$t('mailbox.form.batchAddTitle')"
		:width="500"
		@confirm="onConfirm">
		<bt-form ref="formRef" class="pt-8px" :model="form" :rules="rules">
			<n-form-item :label="$t('mailbox.form.domain')" path="domain">
				<domain-select v-model:value="form.domain" class="flex-1" :is-all="false" :disabled="false">
				</domain-select>
			</n-form-item>
			<n-form-item :label="$t('mailbox.form.prefix')" path="prefix">
				<n-input v-model:value="form.prefix"> </n-input>
			</n-form-item>
			<n-form-item :label="$t('mailbox.form.count')" path="count">
				<n-input-number v-model:value="form.count" class="flex-1" :min="1" :show-button="false">
				</n-input-number>
			</n-form-item>
			<n-form-item v-if="false" :label="$t('mailbox.form.password')" path="password">
				<n-input
					v-model:value="form.password"
					:placeholder="$t('mailbox.form.passwordPlaceholder')">
				</n-input>
			</n-form-item>
			<n-form-item :label="$t('mailbox.form.quota')" path="quota">
				<n-input-group>
					<n-input-number v-model:value="form.quota" class="flex-1" :min="1" :show-button="false">
					</n-input-number>
					<n-select v-model:value="form.unit" class="flex-1" :options="unitOptions"> </n-select>
				</n-input-group>
			</n-form-item>
		</bt-form>
	</bt-modal>
</template>

<script lang="ts" setup>
import { FormRules } from 'naive-ui'
import { createBatchMailbox } from '@/api/modules/mailbox'
import DomainSelect from './DomainSelect.vue'

const emit = defineEmits<{
	refresh: []
}>()

const { t } = useI18n()

const show = ref(false)

const formRef = useTemplateRef('formRef')

const form = reactive({
	domain: null as string | null,
	prefix: '',
	count: 10,
	quota: 5,
	unit: 'GB',
	password: '',
})

const rules: FormRules = {
	domain: {
		trigger: 'change',
		required: true,
		validator: () => {
			if (!form.domain) {
				return new Error(t('mailbox.validation.domainRequired'))
			}
			return true
		},
	},
	prefix: {
		trigger: 'blur',
		required: true,
		validator: () => {
			if (form.prefix.trim().length < 1) {
				return new Error(t('mailbox.validation.prefixRequired'))
			}
			return true
		},
	},
	count: {
		trigger: 'blur',
		required: true,
		validator: () => {
			if (form.count < 1) {
				return new Error(t('mailbox.validation.countRequired'))
			}
			return true
		},
	},
}

const unitOptions = [
	{ label: 'GB', value: 'GB' },
	{ label: 'MB', value: 'MB' },
]

const onConfirm = async () => {
	await formRef.value?.validate()
	await createBatchMailbox(getParams())
	emit('refresh')
}

const getParams = () => {
	return {
		domain: form.domain || '',
		quota: getQuotaByte(form.quota, form.unit),
		prefix: form.prefix,
		count: form.count,
	}
}

/**
 * @description Calculate the byte number based on the domain quota and unit
 * @param quota
 * @param quota_unit
 */
const getQuotaByte = (quota: number, quota_unit: string) => {
	switch (quota_unit) {
		case 'GB':
			quota *= 1024
		case 'MB':
			quota *= 1024 * 1024
	}
	return quota
}

const open = () => {
	resetForm()
	show.value = true
}

const resetForm = () => {
	form.domain = null
	form.prefix = ''
	form.count = 10
	form.quota = 5
	form.unit = 'GB'
	form.password = ''
}

defineExpose({
	open,
})
</script>

<style lang="scss" scoped></style>
