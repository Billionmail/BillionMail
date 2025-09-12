<template>
	<modal :title="t('overview.sendFailDetails.title')" :width="1000" :footer="false">
		<n-data-table
			:loading="loading"
			:max-height="600"
			:data="tableData"
			:columns="columns"
			:row-props="rowProps">
		</n-data-table>
	</modal>
</template>

<script lang="tsx" setup>
import { DataTableColumns, DataTableCreateRowProps, NEllipsis } from 'naive-ui'
import { isArray } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { getFailedList } from '@/api/modules/overview'
import type { Failed } from '../types'

const { t } = useI18n()

const loading = ref(false)

const tableData = ref<Failed[]>([])

const columns = ref<DataTableColumns<Failed>>([
	{
		key: 'recipient',
		title: t('overview.sendFailDetails.columns.recipient'),
		width: 160,
		render: row => {
			return (
				<NEllipsis
					class={row.tooltip ? '' : 'break-all!'}
					line-clamp={row.tooltip ? 999 : 1}
					tooltip={false}>
					{row.recipient}
				</NEllipsis>
			)
		},
	},
	{
		key: 'dsn',
		title: t('overview.sendFailDetails.columns.dsn'),
		width: 60,
	},
	{
		key: 'delay',
		title: t('overview.sendFailDetails.columns.delay'),
		width: 70,
	},
	{
		key: 'delays',
		title: t('overview.sendFailDetails.columns.delays'),
		width: 150,
	},
	{
		key: 'status',
		title: t('overview.sendFailDetails.columns.status'),
		width: 100,
		ellipsis: {
			tooltip: true,
		},
		render: row => {
			return row.status
		},
	},
	{
		key: 'relay',
		title: t('overview.sendFailDetails.columns.relay'),
		width: 200,
		render: row => {
			return (
				<NEllipsis
					class={row.tooltip ? '' : 'break-all!'}
					line-clamp={row.tooltip ? 9999 : 1}
					tooltip={false}>
					{row.relay}
				</NEllipsis>
			)
		},
	},

	{
		key: 'description',
		title: t('overview.sendFailDetails.columns.details'),
		render: row => {
			return (
				<NEllipsis
					class={row.tooltip ? '' : 'break-all!'}
					line-clamp={row.tooltip ? 9999 : 1}
					tooltip={false}>
					{row.description}
				</NEllipsis>
			)
		},
	},
])

const rowProps: DataTableCreateRowProps<Failed> = row => {
	return {
		onMousemove: () => {
			row.tooltip = true
		},
		onMouseleave: () => {
			row.tooltip = false
		},
	}
}

const getTableData = async (domain: string, startTime: number, endTime: number) => {
	try {
		loading.value = true
		const res = await getFailedList({
			domain,
			start_time: startTime / 1000,
			end_time: endTime / 1000,
		})
		tableData.value = isArray<Failed>(res) ? res : []
	} finally {
		loading.value = false
	}
}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ domain: string; startTime: number; endTime: number }>()
			getTableData(state.domain, state.startTime, state.endTime)
		} else {
			tableData.value = []
		}
	},
})
</script>

<style lang="scss" scoped></style>
