<template>
	<n-card class="metric-card" :bordered="false">
		<div class="title">{{ title }}</div>
		<div class="value" :style="{ color: textColor }">{{ value }}{{ unit }}</div>
	</n-card>
</template>

<script setup lang="ts">
defineProps({
	title: {
		type: String,
		default: '',
	},
	value: {
		type: Number,
		default: 0,
	},
	unit: {
		type: String,
		default: '',
	},
	textColor: {
		type: String,
	},
})
</script>

<style lang="scss" scoped>
.metric-card {
	--n-padding-top: 24px;
	--n-padding-bottom: 24px;
	--n-text-color: var(--color-card-text-1);
}

.title {
	margin-bottom: 15px;
	font-size: 18px;
	font-weight: 400;
}

.value {
	font-size: 20px;
}
</style>
