<template>
	<modal :title="t('contacts.subscribers.batchSetTag.title')" :width="500">
		<bt-form class="pt-8px">
			<n-form-item :label="t('contacts.subscribers.batchSetTag.labels.tag')">
				<div class="flex-1 mr-12px">
					<n-select
						v-model:value="form.tag_ids"
						:options="tagOptions"
						:multiple="true"
						:loading="loading"
						max-tag-count="responsive">
					</n-select>
				</div>
				<n-button type="primary" text @click="onCreate">{{ $t('common.actions.create') }}</n-button>
			</n-form-item>
			<n-form-item :label="t('contacts.subscribers.batchSetTag.labels.action')">
				<n-select v-model:value="form.action" :options="actionOptions"></n-select>
			</n-form-item>

			<form-modal></form-modal>
		</bt-form>
	</modal>
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'
import { isObject } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { getTagAll } from '../../tags/service'
import { Tag } from '../../tags/types'
import { batchSetTag } from '@/api/modules/contacts/subscribers'
import TagForm from '../../tags/components/TagForm.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const form = reactive({
	tag_ids: [] as number[],
	action: 1,
})

const tagOptions = ref<SelectOption[]>([])

const actionOptions = computed<SelectOption[]>(() => [
	{
		label: t('contacts.subscribers.batchSetTag.actions.add'),
		value: 1,
	},
	{
		label: t('contacts.subscribers.batchSetTag.actions.remove'),
		value: 2,
	},
])

const loading = ref(false)

const getTagOptions = async () => {
	try {
		loading.value = true
		const res = await getTagAll({})
		if (isObject<{ list: Tag[] }>(res)) {
			const { groupId } = modalApi.getState<{ groupId: number }>()
			tagOptions.value = res.list
				.filter(item => item.group_id === groupId)
				.map(item => ({
					label: item.name,
					value: item.id,
				}))
		}
	} finally {
		loading.value = false
	}
}

const [FormModal, formModalApi] = useModal({
	component: TagForm,
	state: {
		refresh: getTagOptions,
	},
})

const onCreate = () => {
	const { groupId } = modalApi.getState<{ groupId: number }>()
	formModalApi.setState({ row: null, isEdit: false, groupId })
	formModalApi.open()
}

const resetForm = () => {
	form.tag_ids = []
	form.action = 1
	tagOptions.value = []
}

const [Modal, modalApi] = useModal({
	onChangeState: show => {
		if (show) {
			getTagOptions()
		} else {
			resetForm()
		}
	},
	onConfirm: async () => {
		const { ids, refresh } = modalApi.getState<{ ids: number[]; refresh: () => void }>()
		await batchSetTag({
			ids,
			tag_ids: form.tag_ids,
			action: form.action,
		})
		refresh()
	},
})
</script>

<style lang="scss" scoped></style>
