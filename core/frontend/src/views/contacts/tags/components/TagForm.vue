<template>
	<modal :title="title" :width="440">
		<bt-form ref="formRef" class="pt-16px" :model="form" :rules="rules">
			<n-form-item :label="t('contacts.tags.form.fields.name')" path="name">
				<n-input v-model:value="form.name"></n-input>
			</n-form-item>
			<n-form-item :label="t('contacts.tags.form.fields.group')" path="group_id">
				<group-select v-model:value="form.group_id" :disabled="isEdit"></group-select>
			</n-form-item>
		</bt-form>
	</modal>
</template>

<script lang="ts" setup>
import { FormRules } from 'naive-ui'
import { useModal } from '@/hooks/modal/useModal'
import { createTag, updateTag } from '../service'
import type { Tag } from '../types'

import GroupSelect from './GroupSelect.vue'

const { t } = useI18n()

const isEdit = ref(false)

const title = computed(() => {
	return isEdit.value ? t('contacts.tags.form.title.edit') : t('contacts.tags.form.title.create')
})

const formRef = useTemplateRef('formRef')

const tagId = ref(0)

const form = reactive({
	name: '',
	group_id: null as number | undefined | null,
})

const rules = computed<FormRules>(() => ({
	name: {
		required: true,
		trigger: ['blur', 'input'],
		validator: () => {
			if (!form.name) {
				return new Error(t('contacts.tags.form.validation.nameRequired'))
			}
			return true
		},
	},
	group_id: {
		required: true,
		trigger: ['change'],
		validator: () => {
			if (!form.group_id) {
				return new Error(t('contacts.tags.form.validation.groupRequired'))
			}
			return true
		},
	},
}))

const resetForm = () => {
	tagId.value = 0
	form.name = ''
	form.group_id = null
}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ row: Tag | null; isEdit: boolean; groupId: number }>()
			isEdit.value = state.isEdit
			if (state.isEdit && state.row) {
				tagId.value = state.row.id
				form.name = state.row.name
				form.group_id = state.row.group_id
			} else {
				form.group_id = state.groupId || null
			}
		} else {
			resetForm()
		}
	},
	onConfirm: async () => {
		await formRef.value?.validate()
		if (isEdit.value) {
			await updateTag({
				id: tagId.value,
				name: form.name,
			})
		} else {
			await createTag({
				name: form.name,
				group_id: form.group_id ? form.group_id : 0,
			})
		}
		const { refresh } = modalApi.getState<{ refresh: () => void }>()
		refresh()
	},
})
</script>

<style lang="scss" scoped></style>
