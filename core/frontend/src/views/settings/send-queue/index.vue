<template>
	<bt-table-layout>
		<template #toolsLeft>
			<n-button type="primary" @click="fetchTable()">
				{{ $t('overview.sendQueue.buttons.refresh') }}
			</n-button>
			<n-button @click="onClear">{{ $t('overview.sendQueue.buttons.quickClear') }}</n-button>
			<n-button @click="onShowConfig">
				{{ $t('overview.sendQueue.buttons.paramConfig') }}
			</n-button>
		</template>
		<template #table>
			<n-data-table v-bind="tableProps" max-height="540px" :columns="columns"></n-data-table>
		</template>
		<template #pageLeft>
			<bt-table-batch v-bind="batchProps" :options="batchOptions" @select="onSelectBatch">
			</bt-table-batch>
		</template>
		<template #modal>
			<param-config-modal ref="configModalRef"></param-config-modal>
			<queue-logs-modal ref="logsModalRef"></queue-logs-modal>
		</template>
	</bt-table-layout>
</template>

<script lang="tsx" setup>
import { DataTableColumns, NButton, NFlex, SelectOption } from 'naive-ui'
import { confirm, formatTime, getByteUnit } from '@/utils'
import { useDataTable } from '@/hooks/useDataTable'
import {
	getSendQueueList,
	deleteSendQueue,
	resendQueue,
	clearSendQueue,
} from '@/api/modules/overview'
import type { SendQueue } from './types'

import ParamConfigModal from './components/param-config.vue'
import QueueLogsModal from './components/queue-logs.vue'

const { t } = useI18n()

const configModalRef = useTemplateRef('configModalRef')
const logsModalRef = useTemplateRef('logsModalRef')

const onShowConfig = () => {
	configModalRef.value?.open()
}

const onClear = () => {
	confirm({
		title: t('overview.sendQueue.confirm.quickClear.title'),
		content: t('overview.sendQueue.confirm.quickClear.content'),
		confirmType: 'error',
		onConfirm: async () => {
			await clearSendQueue()
			fetchTable()
		},
	})
}

const { tableProps, batchProps, fetchTable } = useDataTable<SendQueue>({
	params: {},
	fetchFn: getSendQueueList,
	rowKey: row => row.queue_id,
})

const columns = ref<DataTableColumns<SendQueue>>([
	{
		width: 40,
		type: 'selection',
	},
	{
		key: 'queue_id',
		title: 'ID',
		width: '8%',
		minWidth: '90px',
		render: row => (
			<NButton
				type="primary"
				text
				onClick={() => {
					logsModalRef.value?.open(row.queue_id)
				}}>
				{row.queue_id}
			</NButton>
		),
	},
	{
		key: 'sender',
		title: t('overview.sendQueue.table.columns.sender'),
		width: '10%',
		minWidth: '120px',
	},
	{
		key: 'recipient',
		title: t('overview.sendQueue.table.columns.recipient'),
		width: '10%',
		minWidth: '120px',
		ellipsis: {
			tooltip: true,
		},
	},
	{
		key: 'arrival_time',
		title: t('overview.sendQueue.table.columns.arrivalTime'),
		width: '12%',
		minWidth: '130px',
		render: row => formatTime(row.arrival_time),
	},
	{
		key: 'message_size',
		title: t('overview.sendQueue.table.columns.messageSize'),
		width: '8%',
		minWidth: '80px',
		render: row => getByteUnit(row.message_size),
	},
	{
		key: 'delay_reason',
		title: t('overview.sendQueue.table.columns.delayReason'),
		ellipsis: {
			tooltip: true,
		},
	},
	{
		key: 'action',
		title: t('overview.sendQueue.table.columns.action'),
		align: 'right',
		width: 120,
		render: row => (
			<NFlex inline={true}>
				<NButton
					type="primary"
					text={true}
					onClick={() => {
						handleResend(row)
					}}>
					{t('overview.sendQueue.buttons.resend')}
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

const handleResend = async (row: SendQueue) => {
	confirm({
		title: t('overview.sendQueue.confirm.resend.title'),
		content: t('overview.sendQueue.confirm.resend.content'),
		onConfirm: async () => {
			await resendQueue({ queue_ids: [row.queue_id] })
			fetchTable()
		},
	})
}

const handleDelete = async (row: SendQueue) => {
	confirm({
		title: t('overview.sendQueue.confirm.delete.title'),
		content: t('overview.sendQueue.confirm.delete.content'),
		confirmType: 'error',
		onConfirm: async () => {
			await deleteSendQueue({ queue_ids: [row.queue_id] })
			fetchTable()
		},
	})
}

const batchOptions: SelectOption[] = [
	{
		label: t('overview.sendQueue.buttons.batchDelete'),
		value: 'delete',
	},
	{
		label: t('overview.sendQueue.buttons.batchResend'),
		value: 'resend',
	},
]

const onSelectBatch = (key: string, keys: string[]) => {
	switch (key) {
		case 'delete':
			handleBatchDelete(keys)
			break
		case 'resend':
			handleBatchResend(keys)
			break
	}
}

const handleBatchDelete = async (keys: string[]) => {
	confirm({
		title: t('overview.sendQueue.confirm.batchDelete.title'),
		content: t('overview.sendQueue.confirm.batchDelete.content', { count: keys.length }),
		confirmType: 'error',
		onConfirm: async () => {
			await deleteSendQueue({ queue_ids: keys })
			fetchTable()
		},
	})
}

const handleBatchResend = async (keys: string[]) => {
	confirm({
		title: t('overview.sendQueue.confirm.batchResend.title'),
		content: t('overview.sendQueue.confirm.batchResend.content', { count: keys.length }),
		onConfirm: async () => {
			await resendQueue({ queue_ids: keys })
			fetchTable()
		},
	})
}
</script>

<style lang="scss" scoped></style>
