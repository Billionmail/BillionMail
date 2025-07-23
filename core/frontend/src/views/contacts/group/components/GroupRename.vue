<template>
	<modal :title="t('contacts.group.rename.title')" width="400">
		<div class="pt-12px">
			<bt-form ref="formRef" :model="form" :rules="rules">
				<n-form-item :label="t('contacts.group.form.name')" path="name">
					<n-input v-model:value="form.name"></n-input>
				</n-form-item>
			</bt-form>
		</div>
	</modal>
</template>

<script lang="ts" setup>
import { useModal } from '@/hooks/modal/useModal'
import { updateGroup } from '@/api/modules/contacts/group'
import type { Group } from '../types/base'

const { t } = useI18n()

const formRef = useTemplateRef('formRef')

const form = reactive({
	group_id: 0,
	name: '',
})

const rules = {
	name: {
		required: true,
		message: t('contacts.group.form.nameRequired'),
		trigger: 'blur',
	},
}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ row: Group | null }>()
			const { row } = state
			if (row) {
				form.group_id = row.id
				form.name = row.name
			}
		} else {
			form.group_id = 0
			form.name = ''
		}
	},
	onConfirm: async () => {
		await formRef.value?.validate()
		await updateGroup(toRaw(form))
		const state = modalApi.getState<{ refresh: () => void }>()
		state?.refresh()
	},
})
</script>
