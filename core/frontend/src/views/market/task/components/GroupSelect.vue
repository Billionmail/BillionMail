<template>
	<div class="flex-1">
		<n-select
			v-model:value="group"
			:options="groupOptions"
			:filterable="true"
			:disabled="disabled"
			:max-tag-count="'responsive'"
			:loading="loading"
			:placeholder="$t('market.task.edit.recipientsPlaceholder')"
			@update:value="handleUpdateGroup">
		</n-select>
	</div>
	<div class="ml-12px">
		<n-button text type="primary" @click="handleShowCreate">
			{{ $t('common.actions.create') }}
		</n-button>
	</div>

	<create-modal />
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'
import { isObject } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { getGroupAll } from '@/api/modules/contacts/group'
import type { Group } from '@/views/contacts/group/types/base'

import CreateGroup from './CreateGroup.vue'

defineProps({
	disabled: {
		type: Boolean as PropType<boolean>,
		default: false,
	},
})

const group = defineModel<number | null>('value', {
	default: () => 0,
})

const label = defineModel<string>('label', {
	default: () => '',
})

const loading = ref(false)

const groupOptions = ref<SelectOption[]>([])

const [CreateModal, createModalApi] = useModal({
	component: CreateGroup,
	state: {
		refresh: () => {
			getGroupOptions()
		},
	},
})

const handleShowCreate = () => {
	createModalApi.open()
}

const handleUpdateGroup = async (val: number, option: SelectOption) => {
	label.value = `${option.label}`
}

const getGroupOptions = async () => {
	try {
		loading.value = true
		const res = await getGroupAll()
		if (isObject<{ list: Group[] }>(res)) {
			groupOptions.value = res.list.map(item => {
				return {
					label: item.name,
					value: item.id,
				}
			})
		}
	} finally {
		loading.value = false
	}
}

getGroupOptions()
</script>

<style lang="scss" scoped></style>
