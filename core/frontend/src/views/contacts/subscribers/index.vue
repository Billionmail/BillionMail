<template>
	<div>
		<subscriber-trends ref="trendRef" :group-id="tableParams.group_id" :status="tableParams.active">
		</subscriber-trends>
		<bt-table-layout>
			<template #toolsLeft>
				<n-button type="primary" @click="handleAdd">
					{{ t('common.actions.import') }}
				</n-button>
				<n-button v-if="tableParams.group_id" @click="handleSettings">
					{{ t('common.actions.settings') }}
				</n-button>
			</template>
			<template #toolsRight>
				<n-radio-group v-model:value="tableParams.active" @update:value="resetTable">
					<n-radio-button :value="-1">
						{{ t('common.all.text') }}
					</n-radio-button>
					<n-radio-button :value="1">
						{{ t('contacts.subscribers.status.subscribed') }}
					</n-radio-button>
					<n-radio-button :value="0">
						{{ t('contacts.subscribers.status.unsubscribed') }}
					</n-radio-button>
				</n-radio-group>
				<div class="w-200px">
					<group-select v-model:value="tableParams.group_id" @update:value="handleUpdateGroup">
					</group-select>
				</div>
				<bt-search
					v-model:value="tableParams.keyword"
					:width="240"
					:placeholder="t('contacts.subscribers.search.emailPlaceholder')"
					@search="resetTable">
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
				<n-button :disabled="tableKeys.length === 0" @click="handleBatchDelete">{{
					$t('common.actions.delete')
				}}</n-button>
			</template>
			<template #pageRight>
				<bt-table-page v-bind="pageProps" @refresh="fetchTable"> </bt-table-page>
			</template>
			<template #modal>
				<import-modal />
				<edit-modal />
			</template>
		</bt-table-layout>
	</div>
</template>

<script lang="tsx" setup>
import { useBrowserLocation } from '@vueuse/core'
import { DataTableColumns, NButton, NFlex, NTag } from 'naive-ui'
import { confirm, formatTime, Message } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { useDataTable } from '@/hooks/useDataTable'
import { deleteSubscriberNdp, getSubscriberListNdp } from '@/api/modules/contacts/subscribers'
import type { Subscriber, SubscriberParams } from './interface'

import GroupSelect from './components/GroupSelect.vue'
import SubscriberTrends from './components/SubscriberTrends.vue'
import SubscriberImport from './components/SubscriberImport.vue'
import SubscriberEdit from './components/SubscriberEdit.vue'

const { t } = useI18n()

const location = useBrowserLocation()

const router = useRouter()

const trendRef = useTemplateRef('trendRef')

const { tableKeys, tableParams, tableProps, pageProps, fetchTable, resetTable } = useDataTable<
	Subscriber,
	SubscriberParams
>({
	params: {
		page: 1,
		page_size: 10,
		group_id: location.value.state.group_id || 0,
		keyword: '',
		active: -1,
	},
	fetchFn: getSubscriberListNdp,
})

// Table columns
const columns = ref<DataTableColumns<Subscriber>>([
	{
		type: 'selection',
		width: 40,
	},
	{
		key: 'email',
		title: t('contacts.subscribers.columns.email'),
		minWidth: 120,
		ellipsis: {
			tooltip: true,
		},
	},
	{
		key: 'status',
		title: 'Status',
		minWidth: 100,
		render: row => {
			if (row.active === 0) {
				return (
					<NTag size="small" type="error" bordered={false}>
						{t('contacts.subscribers.status.unsubscribed')}
					</NTag>
				)
			}
			if (row.active === 1 && row.status === 0) {
				return (
					<NTag size="small" type="default" bordered={false}>
						Unconfirmed
					</NTag>
				)
			}
			return (
				<NTag size="small" type="success" bordered={false}>
					{t('contacts.subscribers.status.subscribed')}
				</NTag>
			)
		},
	},
	{
		key: 'groups',
		title: t('contacts.subscribers.joinGroup'),
		minWidth: 100,
		render: row => {
			return row.group_name || ''
		},
	},
	{
		key: 'create_time',
		title: t('contacts.subscribers.columns.createdAt'),
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

const handleUpdateGroup = () => {
	resetTable()
	nextTick(() => {
		trendRef.value?.getData()
	})
}

const [ImportModal, importModalApi] = useModal({
	component: SubscriberImport,
	state: {
		refresh: fetchTable,
	},
})

// Handle add subscriber
const handleAdd = () => {
	importModalApi.setState({ group_id: tableParams.value.group_id })
	importModalApi.open()
}

const handleSettings = () => {
	if (!tableParams.value.group_id) {
		Message.warning(t('contacts.subscribers.selectGroupHint'))
		return
	}
	router.push(`/contacts/settings/${tableParams.value.group_id}`)
}

const [EditModal, editModalApi] = useModal({
	component: SubscriberEdit,
	state: {
		refresh: fetchTable,
	},
})

// Handle edit
const handleEdit = (row: Subscriber) => {
	editModalApi.setState({ row })
	editModalApi.open()
}

// Handle delete
const handleDelete = (row: Subscriber) => {
	confirm({
		title: t('contacts.subscribers.delete.title'),
		content: t('contacts.subscribers.delete.confirm', { email: row.email }),
		confirmText: t('common.actions.delete'),
		confirmType: 'error',
		onConfirm: async () => {
			await deleteSubscriberNdp({ ids: [row.id] })
			fetchTable()
		},
	})
}

const handleBatchDelete = () => {
	confirm({
		title: 'Batch Delete',
		content: 'Are you sure you want to delete the selected subscribers?',
		confirmText: t('common.actions.delete'),
		confirmType: 'error',
		onConfirm: async () => {
			await deleteSubscriberNdp({ ids: tableKeys.value as number[] })
			fetchTable()
		},
	})
}
</script>

<style lang="scss" scoped>
.subscriber-container {
	padding: 16px;
	background-color: #fff;
	border-radius: 3px;

	.action-bar {
		display: flex;
		justify-content: space-between;
		margin-bottom: 16px;
	}
}
</style>
