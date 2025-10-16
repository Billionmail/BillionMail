<template>
	<div class="flex-1 mr-12px">
		<n-select
			v-model:value="value"
			:loading="loading"
			:tag="true"
			:multiple="true"
			:filterable="true"
			:options="options">
		</n-select>
	</div>
	<n-button type="primary" text @click="onCreate">{{ $t('common.actions.create') }}</n-button>

	<form-modal></form-modal>
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'
import { isObject } from '@/utils'
import { getTagAll } from '../service'
import type { Tag } from '../types'
import { useModal } from '@/hooks/modal/useModal'

import TagForm from './TagForm.vue'

const { groupId } = defineProps({
	groupId: {
		type: Number as PropType<number | null>,
		default: 0,
	},
})

const value = defineModel<number[]>('value', {
	default: () => [],
})

const loading = ref(false)

const tagList = ref<Tag[]>([])

const options = computed<SelectOption[]>(() => {
	return tagList.value
		.filter(item => item.group_id === groupId)
		.map(item => ({
			label: item.name,
			value: item.id,
		}))
})

const getOptions = async () => {
	try {
		loading.value = true
		const res = await getTagAll({})
		if (isObject<{ list: Tag[] }>(res)) {
			tagList.value = res.list
		}
	} finally {
		loading.value = false
	}
}

getOptions()

watch(
	() => groupId,
	val => {
		value.value = tagList.value.filter(item => item.group_id === val).map(item => item.id)
	}
)

const [FormModal, formModalApi] = useModal({
	component: TagForm,
	state: {
		refresh: getOptions,
	},
})

const onCreate = () => {
	formModalApi.setState({ row: null, isEdit: false, groupId })
	formModalApi.open()
}
</script>
