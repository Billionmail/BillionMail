<template>
	<div class="flex gap-10px">
		<div class="flex-center w-40px">
			<n-checkbox
				v-model:checked="checked"
				:disabled="checkedDisabled"
				:indeterminate="indeterminate">
			</n-checkbox>
		</div>
		<n-button
			v-for="item in options"
			:key="item.value"
			:disabled="btnDisabled"
			@click="onClick(item.value as string)">
			{{ item.label }}
		</n-button>
	</div>
</template>

<script lang="ts" setup>
import { DataTableCreateRowKey, DataTableRowData, DataTableRowKey, SelectOption } from 'naive-ui'

const { data, checkedRowKeys, rowKey } = defineProps({
	data: {
		type: Array as PropType<DataTableRowData[]>,
		default: () => [],
	},
	rowKey: {
		type: Function as PropType<DataTableCreateRowKey<any>>,
		required: true,
	},
	options: {
		type: Array as PropType<SelectOption[]>,
		default: () => [],
	},
	checkedRowKeys: {
		type: Array as PropType<DataTableRowKey[]>,
		default: () => [],
	},
})

const emit = defineEmits(['updateCheckedRowKeys', 'select'])

const checked = computed({
	get() {
		return checkedRowKeys.length > 0 && checkedRowKeys.length === data.length
	},
	set(val) {
		if (val) {
			emit(
				'updateCheckedRowKeys',
				data.map(item => rowKey(item))
			)
		} else {
			emit('updateCheckedRowKeys', [])
		}
	},
})

const checkedDisabled = computed(() => {
	return data.length === 0
})

const indeterminate = computed(() => {
	return checkedRowKeys.length > 0 && checkedRowKeys.length < data.length
})

const btnDisabled = computed(() => {
	return checkedRowKeys.length === 0
})

const onClick = (val: string) => {
	emit('select', val, checkedRowKeys)
}
</script>

<style lang="scss" scoped></style>
