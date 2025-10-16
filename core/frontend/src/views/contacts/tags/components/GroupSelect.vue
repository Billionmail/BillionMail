<template>
	<n-select v-model:value="value" :loading="loading" :options="groupOptions"></n-select>
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'
import { isObject } from '@/utils'
import { getGroupAll } from '@/api/modules/contacts/group'
import type { Group } from '../../group/types/base'

const { all } = defineProps({
	all: {
		type: Boolean,
		default: false,
	},
})

const value = defineModel<number | undefined | null>('value')

const { t } = useI18n()

const groupOptions = ref<SelectOption[]>([])

const loading = ref(false)

const getGroupOptions = async () => {
	try {
		loading.value = true
		const res = await getGroupAll()
		if (isObject<{ list: Group[] }>(res)) {
			groupOptions.value = res.list.map(item => ({
				label: item.name,
				value: item.id,
			}))
			if ((value.value === null || value.value === undefined) && res.list.length > 0) {
				value.value = res.list[0].id
			}
			if (all) {
				groupOptions.value.unshift({
					label: t('common.all.text'),
					value: 0,
				})
			}
		}
	} finally {
		loading.value = false
	}
}

getGroupOptions()
</script>
