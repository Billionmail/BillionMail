<template>
	<modal :title="$t('contacts.subscribers.edit.title')" width="600">
		<div class="pt-12px">
			<bt-form ref="formRef" :model="form" :rules="rules">
				<n-grid :cols="12" :x-gap="24">
					<n-form-item-gi :span="8" :label="$t('contacts.subscribers.edit.email')">
						<n-input v-model:value="form.email" :disabled="true"></n-input>
					</n-form-item-gi>
					<n-form-item-gi :span="4" :label="$t('contacts.subscribers.import.subscriptionStatus')">
						<n-select v-model:value="form.active" :options="activeOptions"></n-select>
					</n-form-item-gi>
				</n-grid>
				<n-grid :cols="12" :x-gap="24">
					<n-form-item-gi :span="8" :label="$t('contacts.subscribers.edit.group')" path="group_ids">
						<group-select v-model:value="form.group_ids" :disabled="true"></group-select>
					</n-form-item-gi>
					<n-form-item-gi :span="4" :label="$t('contacts.subscribers.import.status')">
						<n-select v-model:value="form.status" :options="statusOptions"></n-select>
					</n-form-item-gi>
				</n-grid>
				<n-form-item :label="$t('contacts.subscribers.edit.attributes')">
					<n-input v-model:value="form.attribs" type="textarea" :rows="6"></n-input>
				</n-form-item>
			</bt-form>
		</div>
	</modal>
</template>

<script lang="ts" setup>
import { FormRules } from 'naive-ui'
import { Message } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { editContactNdp } from '@/api/modules/contacts/subscribers'
import type { Subscriber } from '../interface'

import GroupSelect from './GroupMultipleSelect.vue'

const { t } = useI18n()

const formRef = useTemplateRef('formRef')

const form = reactive({
	id: 0,
	email: '',
	active: 1,
	status: 1,
	attribs: '',
	group_ids: [] as number[],
})

const rules: FormRules = {
	group_ids: {
		trigger: 'change',
		validator: () => {
			if (form.group_ids.length === 0) {
				return new Error(t('contacts.subscribers.edit.validation.groupRequired'))
			}
			return true
		},
	},
}

const activeOptions = computed(() => [
	{ label: t('contacts.subscribers.edit.statusOptions.subscribe'), value: 1 },
	{ label: t('contacts.subscribers.edit.statusOptions.unsubscribe'), value: 0 },
])

const statusOptions = computed(() => [
	{ label: t('contacts.subscribers.import.statusOptions.confirmed'), value: 1 },
	{ label: t('contacts.subscribers.import.statusOptions.unconfirmed'), value: 0 },
])

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ row: Subscriber | null }>()
			const { row } = state
			if (row) {
				form.id = row.id
				form.email = row.email
				form.active = row.active
				form.status = row.status
				form.group_ids = [row.group_id]
				form.attribs = row.attribs ? JSON.stringify(row.attribs, null, 2) : ''
			}
		} else {
			form.id = 0
			form.email = ''
			form.active = 1
			form.status = 1
			form.group_ids = []
			form.attribs = ''
		}
	},
	onConfirm: async () => {
		await formRef.value?.validate()

		let attribs = {}
		try {
			attribs = form.attribs ? JSON.parse(form.attribs) : {}
		} catch (error) {
			Message.error(`${error}`, { close: true })
			return false
		}
		await editContactNdp({
			id: form.id,
			active: form.active,
			status: form.status,
			attribs: JSON.stringify(attribs),
		})
		const state = modalApi.getState<{ refresh: () => void }>()
		state.refresh()
	},
})
</script>
