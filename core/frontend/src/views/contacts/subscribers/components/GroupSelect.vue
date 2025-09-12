<template>
	<n-select v-model:value="value" :options="groupOptions" :renderTag="renderTag"></n-select>
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'
import { isObject } from '@/utils'
import { getGroupAll } from '@/api/modules/contacts/group'
import type { Group } from '../../group/types/base'

const { t } = useI18n()

const value = defineModel<string | number>('value')

const groupOptions = ref<SelectOption[]>([{ label: t('common.all.text'), value: 0 }])

const renderTag = ({ option }: { option: SelectOption }) => {
	return `${t('contacts.subscribers.select.prefix')}${option.label}`
}

const getGroupOptions = async () => {
	const res = await getGroupAll()
	if (isObject<{ list: Group[] }>(res)) {
		groupOptions.value = res.list.map(item => ({
			label: item.name,
			value: item.id,
		}))
		groupOptions.value.unshift({ label: t('common.all.text'), value: 0 })
	}
}

getGroupOptions()
</script>
