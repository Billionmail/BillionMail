<template>
	<div>
		<bt-table-layout>
			<template #toolsLeft>
				<n-button type="primary" @click="handleShowScan">{{ $t('contacts.suspend.buttons.scanInvalidDomains') }}</n-button>
				<n-button @click="handleShowScanLogs">{{ $t('contacts.suspend.buttons.scanLogs') }}</n-button>
				<n-button @click="handleClear">{{ $t('common.actions.clear') }}</n-button>
				<div class="ml-8px">
					<span class="mr-12px">{{ $t('contacts.suspend.buttons.autoBlockFailedEmails') }}</span>
					<n-switch v-model:value="autoScan" @update:value="handleUpdateAutoScan"></n-switch>
				</div>
			</template>
			<template #toolsRight>
				<bt-search
					v-model:value="tableParams.keyword"
					:width="240"
					:placeholder="$t('contacts.suspend.search.emailPlaceholder')"
					@search="resetTable">
				</bt-search>
			</template>
			<template #table>
				<n-data-table v-bind="tableProps" :columns="columns"> </n-data-table>
			</template>
			<template #pageRight>
				<bt-table-page v-bind="pageProps" @refresh="fetchTable"> </bt-table-page>
			</template>
			<template #modal>
				<scan-modal></scan-modal>
				<scan-logs-modal></scan-logs-modal>
			</template>
		</bt-table-layout>
	</div>
</template>

<script lang="tsx" setup>
import { DataTableColumns, NButton, NFlex } from 'naive-ui'
import { confirm, formatTime, isNumber } from '@/utils'
import { useDataTable } from '@/hooks/useDataTable'
import { useModal } from '@/hooks/modal/useModal'
import {
	clearSuspend,
	deleteSuspend,
	getAutoScan,
	getSuspendList,
	setAutoScan,
} from '@/api/modules/contacts/suspend'
import type { Suspend, SuspendParams } from './types/base'

import Scan from './components/Scan.vue'
import ScanLogs from './components/ScanLogs.vue'

const { t } = useI18n()

const autoScan = ref(false)

const getScanStatus = async () => {
	const res = await getAutoScan()
	if (isNumber(res)) {
		autoScan.value = res === 1
	}
}

getScanStatus()

const handleUpdateAutoScan = async (value: boolean) => {
	await setAutoScan({ oper: value ? 1 : 0 })
}

const [ScanModal, scanModalApi] = useModal({
	component: Scan,
	state: {
		showLogs: () => {
			scanLogsModalApi.open()
		},
	},
})

const handleShowScan = () => {
	scanModalApi.open()
}

const [ScanLogsModal, scanLogsModalApi] = useModal({
	component: ScanLogs,
})

const handleShowScanLogs = () => {
	scanLogsModalApi.open()
}

const handleClear = () => {
	confirm({
		title: t('contacts.suspend.confirm.clear.title'),
		content: t('contacts.suspend.confirm.clear.content'),
		onConfirm: async () => {
			await clearSuspend()
			fetchTable()
		},
	})
}

const { tableParams, tableProps, pageProps, fetchTable, resetTable } = useDataTable<
	Suspend,
	SuspendParams
>({
	params: {
		page: 1,
		page_size: 10,
		status: 1,
		keyword: '',
	},
	fetchFn: getSuspendList,
})

const columns = ref<DataTableColumns<Suspend>>([
	{
		key: 'recipient',
		title: t('contacts.suspend.columns.email'),
	},
	{
		key: 'description',
		title: t('contacts.suspend.columns.description'),
	},
	{
		key: 'state',
		title: t('contacts.suspend.columns.status'),
		render: row => (row.state || row.count >= 3 ? t('contacts.suspend.status.invalid') : t('contacts.suspend.status.checking')),
	},
	{
		key: 'create_time',
		title: t('contacts.suspend.columns.addTime'),
		render: row => formatTime(row.create_time),
	},
	{
		title: t('common.columns.actions'),
		key: 'actions',
		align: 'right',
		width: 100,
		render: row => (
			<NFlex inline={true}>
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

const handleDelete = (row: Suspend) => {
	confirm({
		title: t('contacts.suspend.confirm.delete.title'),
		content: t('contacts.suspend.confirm.delete.content', { email: row.recipient }),
		onConfirm: async () => {
			await deleteSuspend({ id: row.id })
			fetchTable()
		},
	})
}
</script>
