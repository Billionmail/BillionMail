<template>
	<n-pagination
		v-bind="$attrs"
		v-model:page="page"
		v-model:page-size="pageSize"
		:show-size-picker="showSizePicker"
		:show-quick-jumper="showQuickJumper"
		:page-sizes="pageSizes"
		:display-order="['pages', 'size-picker', 'quick-jumper']"
		@update:page="updatePage"
		@update:page-size="updatePageSize">
		<template v-if="showTotal" #suffix="{ itemCount }">
			<span class="ml-8px text-14px"> Total {{ itemCount }} </span>
		</template>
	</n-pagination>
</template>

<script lang="ts" setup>
import { getNumber, getLocalStorage, setLocalStorage } from '@/utils'

interface Props {
	storeKey?: string
	pageSizes?: number[]
	showTotal?: boolean
	showSizePicker?: boolean
	showQuickJumper?: boolean
	// eslint-disable-next-line no-unused-vars
	onUpdatePage?: (page: number) => void
}

const props = withDefaults(defineProps<Props>(), {
	storeKey: '',
	pageSizes: () => [10, 20, 50, 100],
	showTotal: true,
	showSizePicker: true,
	showQuickJumper: true,
})

const emit = defineEmits<{
	refresh: []
}>()

const key = computed(() => {
	const { storeKey } = props
	return storeKey ? `${storeKey}-page` : ''
})

const page = defineModel<number>('page')

const pageSize = defineModel<number>('pageSize')

const updatePage = (val: number) => {
	props.onUpdatePage?.(val)
	emit('refresh')
}

// Switch page size
const updatePageSize = (size: number) => {
	page.value = 1
	props.onUpdatePage?.(1)
	setPageSize(size)
	emit('refresh')
}

const setPageSize = (size: number) => {
	if (key.value) {
		setLocalStorage(key.value, String(size))
	}
}

const initPageSize = () => {
	if (key.value) {
		const size = getLocalStorage(key.value)
		if (size) {
			pageSize.value = getNumber(size)
		}
	}
}

initPageSize()
</script>
