<template>
	<bt-table-layout>
		<template #toolsLeft>
			<n-button type="primary" @click="onShowAdd">{{ t('contacts.tags.addTag') }}</n-button>
			<n-button @click="onShowBulk">{{ t('contacts.tags.bulkTag') }}</n-button>
		</template>
		<template #toolsRight>
			<div class="w-200px">
				<group-select
					v-model:value="tableParams.group_id"
					:all="true"
					@update:value="() => fetchTable(true)">
				</group-select>
			</div>
			<bt-search
				v-model:value="tableParams.keyword"
				:width="240"
				:placeholder="t('contacts.tags.searchPlaceholder')"
				@search="() => fetchTable(true)">
			</bt-search>
		</template>
		<template #table>
			<n-data-table v-bind="tableProps" :columns="columns">
				<template #empty>
					<bt-table-help> </bt-table-help>
				</template>
			</n-data-table>
		</template>
		<template #pageRight>
			<bt-table-page v-bind="pageProps" @refresh="fetchTable"> </bt-table-page>
		</template>
		<template #modal>
			<form-modal></form-modal>
			<bulk-modal></bulk-modal>
		</template>
	</bt-table-layout>
</template>

<script lang="tsx" setup>
import { DataTableColumns, NButton, NFlex } from 'naive-ui'
import { useBrowserLocation } from '@vueuse/core'
import { confirm, formatTime } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { useDataTable } from '@/hooks/useDataTable'
import { deleteTag, getTagList } from './service'
import { Tag, TagParams } from './types'

import GroupSelect from './components/GroupSelect.vue'
import TagForm from './components/TagForm.vue'
import TagBulk from './components/TagBulk.vue'

const location = useBrowserLocation()

const { t } = useI18n()

const { tableProps, pageProps, tableParams, fetchTable } = useDataTable<Tag, TagParams>({
	params: {
		keyword: '',
		group_id: location.value.state.group_id || 0,
		page: 1,
		page_size: 10,
	},
	useParams: params => {
		return {
			...params,
			group_id: params.group_id || undefined,
		}
	},
	fetchFn: getTagList,
})

const columns = ref<DataTableColumns<Tag>>([
	{
		key: 'name',
		title: t('contacts.tags.columns.name'),
		minWidth: 120,
		ellipsis: {
			tooltip: true,
		},
		render: row => (
			<NButton
				type="primary"
				text={true}
				onClick={() => {
					onView(row)
				}}>
				{row.name}
			</NButton>
		),
	},
	{
		key: 'group_name',
		title: t('contacts.tags.columns.groupName'),
		minWidth: 120,
		ellipsis: {
			tooltip: true,
		},
	},
	{
		key: 'create_time',
		title: t('contacts.tags.columns.createTime'),
		minWidth: 140,
		render: row => formatTime(row.create_time),
	},
	{
		key: 'action',
		title: t('contacts.tags.columns.actions'),
		align: 'right',
		width: 180,
		render: row => (
			<NFlex inline={true}>
				<NButton
					type="primary"
					text={true}
					onClick={() => {
						onView(row)
					}}>
					{t('common.actions.view')}
				</NButton>
				<NButton
					type="primary"
					text={true}
					onClick={() => {
						onEditTag(row)
					}}>
					{t('common.actions.edit')}
				</NButton>
				<NButton
					type="error"
					text={true}
					onClick={() => {
						onDelTag(row)
					}}>
					{t('common.actions.delete')}
				</NButton>
			</NFlex>
		),
	},
])

const router = useRouter()

const onView = (row: Tag) => {
	router.push({
		path: '/contacts/subscribers',
		state: { group_id: row.group_id, tag_id: row.id },
	})
}

const [FormModal, formModalApi] = useModal({
	component: TagForm,
	state: {
		refresh: fetchTable,
	},
})

const onShowAdd = () => {
	formModalApi.setState({ row: null, isEdit: false, groupId: tableParams.value.group_id })
	formModalApi.open()
}

const onEditTag = (row: Tag) => {
	formModalApi.setState({ row, isEdit: true })
	formModalApi.open()
}

const onDelTag = (row: Tag) => {
	confirm({
		title: t('contacts.tags.delete.title'),
		content: t('contacts.tags.delete.confirm', { name: row.name }),
		onConfirm: async () => {
			await deleteTag({ id: row.id })
			fetchTable()
		},
	})
}

const [BulkModal, bulkModalApi] = useModal({
	component: TagBulk,
	state: {
		refresh: fetchTable,
	},
})

const onShowBulk = () => {
	bulkModalApi.open()
}
</script>

<style lang="scss" scoped></style>
