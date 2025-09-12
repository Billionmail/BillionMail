<template>
	<n-spin class="mb-16px" :show="loading">
		<div class="text-center fw-bold text-16px text-default">{{ t('contacts.subscribers.trends.title') }}</div>
		<div class="w-96% h-160px mx-auto">
			<bt-charts :options="chartOptions" />
		</div>
	</n-spin>
</template>

<script lang="ts" setup>
import { isArray, isObject } from '@/utils'
import { getSubscriberTrend } from '@/api/modules/contacts/subscribers'
import type { ECOptionLine } from '@/types/chart'
import type { SubscriberTrend } from '../interface'

const { groupId } = defineProps({
	groupId: {
		type: Number,
	},
})

const loading = ref(false)

const subscribe = ref<SubscriberTrend[]>([])

const { t } = useI18n()

const chartOptions = computed<ECOptionLine>(() => {
	return {
		tooltip: {
			trigger: 'axis',
			order: 'seriesDesc',
			axisPointer: {
				type: 'shadow',
			},
		},
		grid: {
			top: '16%',
			left: '2%',
			right: '2%',
			bottom: '4%',
			containLabel: true,
		},
		xAxis: {
			data: subscribe.value.map(item => item.month),
			axisTick: {
				show: false,
			},
			axisLabel: {
				color: '#6b7280',
				fontSize: 12,
			},
		},
		yAxis: {
			type: 'value',
			minInterval: 1,
			axisLabel: {
				color: '#6b7280',
				fontSize: 12,
			},
		},
		series: [
			{
				name: t('contacts.subscribers.trends.subscriber'),
				type: 'line',
				data: subscribe.value.map(item => item.count),
				itemStyle: {
					color: '#20a53a',
				},
				smooth: true,
				showSymbol: false,
				sampling: 'average',
				areaStyle: {
					color: {
						type: 'linear',
						x: 0,
						y: 0,
						x2: 0,
						y2: 1,
						global: false,
						colorStops: [
							{ offset: 0, color: 'rgba(32, 164, 58, 0.4)' },
							{ offset: 0.7, color: 'rgba(32, 164, 58, 0)' },
						],
					},
				},
			},
		],
	}
})

const getData = async () => {
	try {
		loading.value = true
		const res = await getSubscriberTrend({ group_id: groupId })
		if (isObject<{ subscribe: SubscriberTrend[]; unsubscribe: SubscriberTrend[] }>(res)) {
			subscribe.value = isArray(res.subscribe) ? res.subscribe : []
		}
	} finally {
		loading.value = false
	}
}

getData()

defineExpose({
	getData,
})
</script>
