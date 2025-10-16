<template>
	<div class="w-80px">
		<n-select v-model:value="value" :options="activeOptions" @update:value="handleUpdateValue">
		</n-select>
	</div>
	<div v-show="value !== -1" class="w-120px">
		<n-select v-model:value="time" :options="timeOptions"> </n-select>
	</div>
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'

const { t } = useI18n()

const value = defineModel<number>('value', {
	default: -1,
})

const activeOptions = computed<SelectOption[]>(() => [
	{
		label: t('contacts.subscribers.activeSelect.options.all'),
		value: -1,
	},
	{
		label: t('contacts.subscribers.activeSelect.options.yes'),
		value: 1,
	},
	{
		label: t('contacts.subscribers.activeSelect.options.no'),
		value: 0,
	},
])

const time = defineModel<number>('time')

const timeOptions = computed<SelectOption[]>(() => [
	{
		label: t('contacts.subscribers.activeSelect.timeOptions.past7Days'),
		value: 7,
	},
	{
		label: t('contacts.subscribers.activeSelect.timeOptions.pastMonth'),
		value: 30,
	},
	{
		label: t('contacts.subscribers.activeSelect.timeOptions.past90Days'),
		value: 90,
	},
	{
		label: t('contacts.subscribers.activeSelect.timeOptions.pastHalfYear'),
		value: 180,
	},
	{
		label: t('contacts.subscribers.activeSelect.timeOptions.pastYear'),
		value: 365,
	},
])

const handleUpdateValue = (value: number) => {
	if (value === -1) {
		time.value = 0
	} else {
		time.value = 365
	}
}
</script>

<style lang="scss" scoped></style>
