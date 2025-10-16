<template>
	<n-spin class="mb-16px" :show="loading">
		<div class="text-center fw-bold text-16px text-default">
			{{ t('contacts.subscribers.trends.title') }}
		</div>
		<div class="w-96% h-160px mx-auto">
			<bt-charts :options="chartOptions" />
		</div>
	</n-spin>
</template>

<script lang="ts" setup>
import { isArray, isObject } from '@/utils'
import { getSubscriberTrend } from '@/api/modules/contacts/subscribers'
import type { ECOptionLine } from '@/types/chart'
import type { SubscriberParams, SubscriberTrend } from '../interface'

const { params } = defineProps({
	params: {
		type: Object as PropType<SubscriberParams>,
		default: () => ({
			page: 1,
			page_size: 10,
			group_id: 0,
			keyword: '',
			active: -1,
			last_active_status: -1,
			time_interval: 0,
			tags: [],
		}),
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
			data: subscribe.value.map(item => item.date),
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
		const res = await getSubscriberTrend({
			group_id: params.group_id,
			active: params.active,
			last_active_status: params.last_active_status,
			time_interval: params.time_interval,
			tags: params.tags.join(','),
		})
		if (
			isObject<{
				time_granularity: string
				daily_data: SubscriberTrend[]
				monthly_data: SubscriberTrend[]
			}>(res)
		) {
			if (res.time_granularity === 'monthly') {
				subscribe.value = isArray(res.monthly_data) ? res.monthly_data : []
			} else if (res.time_granularity === 'daily') {
				subscribe.value = isArray(res.daily_data) ? res.daily_data : []
			}
		}
	} finally {
		loading.value = false
	}
}

onMounted(() => {
	getData()
})

defineExpose({
	getData,
})
</script>
