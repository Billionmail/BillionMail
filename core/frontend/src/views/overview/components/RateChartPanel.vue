<template>
	<n-card :title="$t('overview.rate.openRate')">
		<line-chart
			chart-color="#1a519b"
			:date-type="open.column_type"
			:chart-name="$t('overview.rate.openRate')"
			:chart-data="openRateData">
		</line-chart>
	</n-card>
	<n-card :title="$t('overview.rate.clickRate')">
		<line-chart
			chart-color="#1a519b"
			:date-type="click.column_type"
			:chart-name="$t('overview.rate.clickRate')"
			:chart-data="clickRateData">
		</line-chart>
	</n-card>
	<n-card :title="$t('overview.rate.bounceRate')">
		<line-chart
			chart-color="#20a53a"
			:date-type="bounce.column_type"
			:chart-name="$t('overview.rate.bounceRate')"
			:chart-data="bounceRateData">
		</line-chart>
	</n-card>
</template>

<script setup lang="ts">
import { PropType } from 'vue'
import { formatTime } from '@/utils'
import { MailOverview } from '../types'

import LineChart from './LineChart.vue'

const { open, click, bounce } = defineProps({
	bounce: {
		type: Object as PropType<MailOverview['bounce_rate_chart']>,
		required: true,
	},
	click: {
		type: Object as PropType<MailOverview['click_rate_chart']>,
		required: true,
	},
	open: {
		type: Object as PropType<MailOverview['open_rate_chart']>,
		required: true,
	},
})

const getChartTime = (type: string, x: number) => {
	let date = new Date()
	let format = ''
	if (type === 'hourly') {
		date.setMinutes(0)
		date.setSeconds(0)
		date.setHours(x)
		format = 'yyyy-MM-dd HH:mm'
	} else if (type === 'daily') {
		date = new Date(x * 1000)
		format = 'yyyy-MM-dd'
	}
	return formatTime(date, format)
}

const openRateData = computed(() => {
	return open.data.map(item => {
		return [getChartTime(open.column_type, item.x), item.open_rate] as [string, number]
	})
})

const clickRateData = computed(() => {
	return click.data.map(item => {
		return [getChartTime(click.column_type, item.x), item.click_rate] as [string, number]
	})
})

const bounceRateData = computed(() => {
	return bounce.data.map(item => {
		return [getChartTime(bounce.column_type, item.x), item.bounce_rate] as [string, number]
	})
})
</script>
