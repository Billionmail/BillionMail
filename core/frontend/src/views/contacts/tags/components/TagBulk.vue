<template>
	<modal :title="t('contacts.tags.bulk.title')" width="560">
		<bt-form ref="formRef" class="pt-16px" :model="form">
			<n-form-item :label="t('contacts.tags.bulk.form.group')" path="group_id">
				<group-select v-model:value="form.group_id" />
			</n-form-item>
			<n-form-item :label="t('contacts.tags.bulk.form.tags')" path="tag_ids">
				<tag-select v-model:value="form.tag_ids" :groupId="form.group_id" />
			</n-form-item>
			<n-form-item :label="t('contacts.tags.bulk.form.emails')" path="data">
				<n-input
					v-model:value="form.data"
					type="textarea"
					:rows="5"
					:placeholder="t('contacts.tags.bulk.form.emailsPlaceholder')">
				</n-input>
			</n-form-item>
			<n-form-item :label="t('contacts.tags.bulk.form.action')" path="mark_include">
				<n-select v-model:value="form.mark_include" :options="actionOptions"></n-select>
			</n-form-item>
		</bt-form>
	</modal>
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'
import { useModal } from '@/hooks/modal/useModal'
import { bulkSetTag } from '../service'

import GroupSelect from './GroupSelect.vue'
import TagSelect from './TagSelect.vue'

const { t } = useI18n()

const form = reactive({
	group_id: null as number | null,
	tag_ids: [] as number[],
	data: '',
	mark_include: 1,
})

const actionOptions = computed<SelectOption[]>(() => [
	{
		label: t('contacts.tags.bulk.actions.tagThese'),
		value: 1,
	},
	{
		label: t('contacts.tags.bulk.actions.tagExcept'),
		value: 0,
	},
])

const resetForm = () => {
	form.group_id = null
	form.tag_ids = []
	form.data = ''
	form.mark_include = 1
}

const [Modal] = useModal({
	onChangeState: () => {
		resetForm()
	},
	onConfirm: async () => {
		await bulkSetTag({
			group_id: form.group_id || 0,
			tag_ids: form.tag_ids,
			data: form.data,
			mark_include: form.mark_include,
		})
	},
})
</script>

<style lang="scss" scoped></style>
