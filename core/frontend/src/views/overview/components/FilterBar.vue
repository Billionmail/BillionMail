<template>
	<div class="filter-bar">
		<div class="w-260px">
			<n-select v-model:value="domain" :options="domainOptions"></n-select>
		</div>

		<div class="date-filters">
			<n-radio-group v-model:value="activeFilter" @update:value="setFilter">
				<n-radio-button value="today">{{ $t('common.time.today') }}</n-radio-button>
				<n-radio-button value="yesterday">{{ $t('common.time.yesterday') }}</n-radio-button>
				<n-radio-button value="last7days">{{ $t('common.time.last7days') }}</n-radio-button>
			</n-radio-group>
			<div class="w-240px">
				<n-date-picker
					:value="dateRange"
					type="daterange"
					:is-date-disabled="dateDisabled"
					@update:value="onDateRangeChange">
				</n-date-picker>
			</div>
		</div>
	</div>
</template>

<script setup lang="ts">
import { addDays, startOfDay, endOfDay } from 'date-fns'
import { getDayTimeRange, isArray } from '@/utils'
import { getDomainAll } from '@/api/modules/domain'
import { MailDomain } from '@/views/domain/interface'

const { t } = useI18n()

const domain = defineModel<string>('domain')

const dateRange = defineModel<[number, number]>('dateRange')

const domainOptions = ref([{ label: t('common.all.domain'), value: '' }])

const activeFilter = ref('today')

const dateDisabled = (ts: number) => {
	const today = new Date()
	const before = addDays(today, -30)
	return startOfDay(before).getTime() > ts || endOfDay(today).getTime() < ts
}

const setFilter = (filter: string) => {
	switch (filter) {
		case 'today':
			dateRange.value = getDayTimeRange()
			break
		case 'yesterday':
			dateRange.value = getDayTimeRange(addDays(new Date(), -1))
			break
		case 'last7days':
			dateRange.value = getLastSevenDaysRange()
			break
	}
}

const getLastSevenDaysRange = (): [number, number] => {
	const today = new Date()
	const end = endOfDay(today)
	const start = startOfDay(addDays(today, -6))
	return [start.getTime(), end.getTime()]
}

const onDateRangeChange = (val: [number, number]) => {
	activeFilter.value = 'custom'
	dateRange.value = [startOfDay(val[0]).getTime(), endOfDay(val[1]).getTime()]
}

const getDomainOptions = async () => {
	const res = await getDomainAll()
	if (isArray<MailDomain>(res)) {
		domainOptions.value = res.map(item => ({
			label: item.domain,
			value: item.domain,
		}))
		domainOptions.value.unshift({ label: t('common.all.domain'), value: '' })
	}
}

onMounted(() => {
	getDomainOptions()
})
</script>

<style lang="scss" scoped>
.filter-bar {
	display: flex;
	flex-wrap: wrap;
	justify-content: space-between;
	gap: 10px;
	margin-bottom: 20px;
}

.date-filters {
	display: flex;
	flex-wrap: wrap;
	gap: 10px;
}

@media (max-width: 768px) {
	.filter-bar {
		flex-direction: column;
		align-items: stretch;
	}

	.w-260px,
	.date-filters .w-240px {
		width: 100%;
	}
}
</style>
