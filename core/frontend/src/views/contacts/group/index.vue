<template>
	<bt-table-layout>
		<template #toolsLeft>
			<n-button type="primary" @click="handleAdd">Add group</n-button>
		</template>
		<template #toolsRight>
			<bt-search
				v-model:value="tableParams.keyword"
				:width="280"
				:placeholder="t('contacts.group.search.namePlaceholder')"
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
		<template #pageLeft>
			<bt-table-batch v-bind="batchProps" :options="batchOptions" @select="handleBatchSelect">
			</bt-table-batch>
		</template>
		<template #pageRight>
			<bt-table-page v-bind="pageProps" @refresh="fetchTable"> </bt-table-page>
		</template>
		<template #modal>
			<add-modal />
			<rename-modal />
		</template>
	</bt-table-layout>
</template>

<script lang="tsx" setup>
import { DataTableColumns, NButton, NFlex, NSelect, NTag } from 'naive-ui'
import { confirm, formatTime } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { useDataTable } from '@/hooks/useDataTable'
import { getGroupList, deleteGroup, exportGroup } from '@/api/modules/contacts/group'
import type { Group, GroupParams } from './types/base.ts'

import GroupAdd from './components/GroupAdd.vue'
import GroupRename from './components/GroupRename.vue'

const { t } = useI18n()

const router = useRouter()

const { tableProps, pageProps, batchProps, tableParams, fetchTable } = useDataTable<
	Group,
	GroupParams
>({
	params: {
		page: 1,
		page_size: 10,
		keyword: '',
	},
	fetchFn: getGroupList,
})

const columns = ref<DataTableColumns<Group>>([
	{
		type: 'selection',
	},
	{
		key: 'name',
		title: t('contacts.group.columns.name'),
		minWidth: 120,
		render: row => (
			<NButton
				text
				type="primary"
				onClick={() => {
					router.push({
						path: '/contacts/subscribers',
						state: { group_id: row.id },
					})
				}}>
				{row.name}
			</NButton>
		),
	},
	{
		key: 'total_count',
		title: t('contacts.group.columns.subscribers'),
		minWidth: 100,
		render: row => (
			<NTag size="small" type="primary" bordered={false}>
				{row.total_count - row.unsubscribe_count}
			</NTag>
		),
	},
	// {
	// 	key: 'unsubscribe_count',
	// 	title: t('contacts.group.columns.unsubscribe'),
	// 	minWidth: 100,
	// 	render: row => row.unsubscribe_count || 0,
	// },
	{
		key: 'double_optin',
		title: t('contacts.group.columns.type'),
		minWidth: 100,
		render: row =>
			row.double_optin === 1
				? t('contacts.group.type.doubleOptin')
				: t('contacts.group.type.singleOptin'),
	},
	{
		key: 'create_time',
		title: t('contacts.group.columns.createdAt'),
		minWidth: 140,
		render: row => formatTime(row.create_time),
	},
	{
		title: t('common.columns.actions'),
		key: 'actions',
		align: 'right',
		width: 180,
		render: row => (
			<NFlex inline={true}>
				<NButton
					type="primary"
					text={true}
					onClick={() => {
						handleSettings(row)
					}}>
					{t('common.actions.settings')}
				</NButton>
				<NButton
					type="primary"
					text={true}
					onClick={() => {
						handleEdit(row)
					}}>
					{t('common.actions.edit')}
				</NButton>
				<NButton
					type="error"
					text={true}
					onClick={() => {
						handleDelete(row)
					}}>
					{t('common.actions.delete')}
				</NButton>
			</NFlex>
		),
	},
])

const batchOptions = [
	{
		label: t('common.actions.export'),
		value: 'export',
	},
]

const handleBatchSelect = (key: string, keys: number[]) => {
	switch (key) {
		case 'export':
			handleBatchExport(keys)
			break
	}
}

const exportFormats = ref([
	{
		label: 'CSV',
		value: 'csv',
	},
	{
		label: 'TXT',
		value: 'txt',
	},
])

const handleBatchExport = (keys: number[]) => {
	const format = ref('csv')
	confirm({
		title: t('contacts.group.export.title'),
		content: () => (
			<>
				<div class="mb-10px">{t('contacts.group.export.confirm', { count: keys.length })}</div>
				<div class="flex">
					<NSelect
						value={format.value}
						options={exportFormats.value}
						onUpdate:value={val => {
							format.value = val
						}}
					/>
				</div>
			</>
		),
		onConfirm: async () => {
			await exportGroup({
				format: format.value,
				include_unsubscribe: true,
				group_ids: keys,
				export_type: 1,
			})
		},
	})
}

const [AddModal, addModalApi] = useModal({
	component: GroupAdd,
	state: {
		refresh: fetchTable,
	},
})

const handleAdd = () => {
	addModalApi.open()
}

const handleSettings = (row: Group) => {
	router.push(`/contacts/settings/${row.id}`)
}

const [RenameModal, renameModalApi] = useModal({
	component: GroupRename,
	state: {
		refresh: fetchTable,
	},
})

const handleEdit = (row: Group) => {
	renameModalApi.setState({ row })
	renameModalApi.open()
}

const handleDelete = (row: Group) => {
	confirm({
		title: t('contacts.group.delete.title'),
		content: t('contacts.group.delete.confirm', { name: row.name }),
		confirmText: t('common.actions.delete'),
		confirmType: 'error',
		onConfirm: async () => {
			await deleteGroup({ group_ids: [row.id] })
			fetchTable()
		},
	})
}
</script>

<style lang="scss" scoped></style>
