<template>
	<bt-table-layout>
		<template #toolsLeft>
			<div class="w-240px">
				<n-select
					v-model:value="tableParams.type"
					:filterable="true"
					:options="typeOptions"
					@update:value="() => resetTable()">
				</n-select>
			</div>
			<bt-search
				v-model:value="tableParams.keyword"
				:placeholder="$t('logs.search.placeholder')"
				@search="() => resetTable()">
			</bt-search>
		</template>
		<template #table>
			<n-data-table v-bind="tableProps" :columns="columns"></n-data-table>
		</template>
		<template #pageRight>
			<bt-table-page v-bind="pageProps" @refresh="fetchTable"> </bt-table-page>
		</template>
	</bt-table-layout>
</template>

<script lang="ts" setup>
import { DataTableColumns, SelectOption } from 'naive-ui'
import { formatTime, isObject } from '@/utils'
import { useDataTable } from '@/hooks/useDataTable'
import { getLogsList, getLogsType } from './controller'
import type { Logs } from './types'

const { t } = useI18n()

const columns = ref<DataTableColumns<Logs>>([
	{
		key: 'username',
		title: t('logs.table.columns.username'),
		width: '10%',
		minWidth: '120px',
		ellipsis: {
			tooltip: true,
		},
	},
	{
		key: 'type',
		title: t('logs.table.columns.type'),
		width: '12%',
		minWidth: '140px',
	},
	{
		key: 'ip',
		title: 'IP',
		width: '10%',
		minWidth: '120px',
	},
	{
		key: 'addtime',
		title: t('logs.table.columns.operatingTime'),
		width: 160,
		render: row => {
			return formatTime(row.addtime)
		},
	},
	{
		key: 'log',
		title: t('logs.table.columns.details'),
		ellipsis: {
			tooltip: true,
		},
	},
])

const { tableParams, tableProps, pageProps, fetchTable, resetTable } = useDataTable<Logs>({
	params: {
		type: '',
		page: 1,
		page_size: 10,
	},
	immediate: true,
	fetchFn: getLogsList,
})

const typeOptions = ref<SelectOption[]>([])

const getTypeOptions = async () => {
	const res = await getLogsType()
	if (isObject<Record<string, string>>(res)) {
		typeOptions.value = Object.entries(res).map(([, value]) => ({
			label: value,
			value: value,
		}))
		typeOptions.value.unshift({
			label: t('logs.filter.all'),
			value: '',
		})
	}
}

getTypeOptions()
</script>

<style lang="scss" scoped></style>
