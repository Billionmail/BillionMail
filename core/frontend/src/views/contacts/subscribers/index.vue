<template>
	<div>
		<subscriber-trends ref="trendRef" :params="tableParams"> </subscriber-trends>
		<bt-table-layout>
			<template #toolsLeft>
				<span>{{ $t('contacts.subscribers.select.prefix') }}</span>
				<div class="w-140px">
					<group-select v-model:value="tableParams.group_id" @update:value="handleUpdateGroup">
					</group-select>
				</div>
				<span>{{ t('contacts.subscribers.labels.status') }}</span>
				<div class="w-140px">
					<n-select
						v-model:value="tableParams.active"
						:options="activeOptions"
						@update:value="() => resetTableAndTrend()">
					</n-select>
				</div>
				<span>{{ t('contacts.subscribers.labels.tags') }}</span>
				<div class="w-200px">
					<tag-select
						v-model:value="tableParams.tags"
						:disabled="tableParams.group_id === 0"
						:group-id="tableParams.group_id"
						@update:value="() => resetTableAndTrend()">
					</tag-select>
				</div>
				<span>{{ t('contacts.subscribers.labels.active') }}</span>
				<active-select
					v-model:value="tableParams.last_active_status"
					v-model:time="tableParams.time_interval"
					@update:value="() => resetTableAndTrend()"
					@update:time="() => resetTableAndTrend()">
				</active-select>
			</template>
			<template #pageLeft>
				<bt-table-batch v-bind="batchProps" :options="batchOptions" @select="handleBatchSelect">
				</bt-table-batch>
			</template>
			<template #toolsRight>
				<bt-search
					v-model:value="tableParams.keyword"
					:width="240"
					:placeholder="t('contacts.subscribers.search.emailPlaceholder')"
					@search="resetTable">
				</bt-search>
				<n-button type="primary" @click="handleAdd">
					{{ t('common.actions.import') }}
				</n-button>
				<n-button v-if="tableParams.group_id" @click="handleSettings">
					{{ t('common.actions.settings') }}
				</n-button>
			</template>
			<template #table>
				<n-data-table v-bind="tableProps" :columns="columns">
					<template #empty>
						<bt-table-help> </bt-table-help>
					</template>
				</n-data-table>
			</template>
			<!-- <template #pageLeft>
				<n-button :disabled="tableKeys.length === 0" @click="handleBatchDelete">
					{{ $t('common.actions.delete') }}
				</n-button>
			</template> -->
			<template #pageRight>
				<bt-table-page v-bind="pageProps" @refresh="fetchTable"> </bt-table-page>
			</template>
			<template #modal>
				<import-modal />
				<edit-modal />
				<set-tag-modal />
			</template>
		</bt-table-layout>
	</div>
</template>

<script lang="tsx" setup>
import { useBrowserLocation, useTimeAgo } from '@vueuse/core'
import { DataTableColumns, NButton, NFlex, NTag } from 'naive-ui'
import { confirm, Message } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { useDataTable } from '@/hooks/useDataTable'
import { deleteSubscriberNdp, getSubscriberListNdp } from '@/api/modules/contacts/subscribers'
import type { Subscriber, SubscriberParams } from './interface'

import GroupSelect from './components/GroupSelect.vue'
import TagSelect from './components/TagSelect.vue'
import ActiveSelect from './components/ActiveSelect.vue'
import SubscriberTrends from './components/SubscriberTrends.vue'
import SubscriberImport from './components/SubscriberImport.vue'
import SubscriberEdit from './components/SubscriberEdit.vue'
import BatchSetTag from './components/BatchSetTag.vue'

const { t } = useI18n()

const location = useBrowserLocation()

const router = useRouter()

const trendRef = useTemplateRef('trendRef')

const activeOptions = computed(() => [
	{
		label: t('common.all.text'),
		value: -1,
	},
	{
		label: t('contacts.subscribers.status.subscribed'),
		value: 1,
	},
	{
		label: t('contacts.subscribers.status.unsubscribed'),
		value: 0,
	},
])

const { tableParams, tableProps, batchProps, pageProps, fetchTable, resetTable } = useDataTable<
	Subscriber,
	SubscriberParams
>({
	params: {
		page: 1,
		page_size: 10,
		group_id: location.value.state.group_id || 0,
		keyword: '',
		active: -1,
		last_active_status: -1,
		time_interval: 0,
		tags: location.value.state.tag_id ? [location.value.state.tag_id] : [],
	},
	useParams: params => {
		return {
			...params,
			tags: params.tags.join(','),
		}
	},
	fetchFn: getSubscriberListNdp,
})

// Table columns
const columns = computed<DataTableColumns<Subscriber>>(() => [
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
		title: t('contacts.subscribers.labels.status').replace('：', ''),
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
						{t('contacts.subscribers.status.unconfirmed')}
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
		key: 'last_active_at',
		title: t('contacts.subscribers.columns.lastActiveAt'),
		minWidth: 100,
		render: row => {
			if (row.last_active_at) {
				const timeAgo = useTimeAgo(new Date(row.last_active_at * 1000))
				return timeAgo.value
			}
			return '--'
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
		key: 'tags',
		title: t('contacts.subscribers.tags'),
		minWidth: 100,
		render: row => {
			if (!row.tags || row.tags.length === 0) {
				return '--'
			}
			return (
				<NFlex inline={true}>
					{row.tags.map(item => (
						<NTag key={item.id} size="small" bordered={false}>
							{item.name}
						</NTag>
					))}
				</NFlex>
			)
		},
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

const resetTableAndTrend = () => {
	resetTable()
	trendRef.value?.getData()
}

const handleUpdateGroup = () => {
	tableParams.value.tags = []
	resetTableAndTrend()
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

const batchOptions = computed(() => [
	{
		label: t('common.actions.delete'),
		value: 'delete',
	},
	{
		label: t('contacts.subscribers.actions.setTag'),
		value: 'tag',
		disabled: tableParams.value.group_id === 0,
	},
])

const handleBatchSelect = (key: string, keys: number[]) => {
	switch (key) {
		case 'delete':
			handleBatchDelete(keys)
			break
		case 'tag':
			handleBatchSetTag(keys)
			break
	}
}

const handleBatchDelete = (keys: number[]) => {
	confirm({
		title: t('contacts.subscribers.batchDelete.title'),
		content: t('contacts.subscribers.batchDelete.confirm'),
		confirmText: t('common.actions.delete'),
		confirmType: 'error',
		onConfirm: async () => {
			await deleteSubscriberNdp({ ids: keys })
			fetchTable()
		},
	})
}

const [SetTagModal, setTagModalApi] = useModal({
	component: BatchSetTag,
	state: {
		refresh: fetchTable,
	},
})

const handleBatchSetTag = (keys: number[]) => {
	setTagModalApi.setState({
		ids: keys,
		groupId: tableParams.value.group_id,
	})
	setTagModalApi.open()
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
