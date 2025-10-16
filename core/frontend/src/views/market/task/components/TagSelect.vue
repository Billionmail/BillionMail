<template>
	<n-select
		v-model:value="tag"
		:options="tagOptions"
		:disabled="disabled"
		:multiple="true"
		:filterable="true"
		:max-tag-count="'responsive'">
	</n-select>
	<div class="ml-12px">
		<n-button text type="primary" @click="handleCreate">
			{{ $t('common.actions.create') }}
		</n-button>
	</div>
</template>

<script lang="ts" setup>
import { SelectOption } from 'naive-ui'
import { getTagAll } from '@/views/contacts/tags/service'
import { Tag } from '@/views/contacts/tags/types'
import { isObject } from '@/utils'

const { groupId } = defineProps({
	groupId: {
		type: Number as PropType<number | null>,
		default: null,
	},
	disabled: {
		type: Boolean as PropType<boolean>,
		default: false,
	},
})

const tag = defineModel<number[]>('value', {
	default: () => [],
})

const router = useRouter()

const tagList = ref<Tag[]>([])

const tagOptions = computed<SelectOption[]>(() => {
	return tagList.value
		.filter(item => item.group_id === groupId)
		.map(item => ({
			value: item.id,
			label: item.name,
		}))
})

const getOptions = async () => {
	const res = await getTagAll({})
	if (isObject<{ list: Tag[] }>(res)) {
		tagList.value = res.list
	}
}

const handleCreate = () => {
	router.push('/contacts/tags')
}

watch(
	() => groupId,
	() => {
		tag.value = []
		// tag.value = tagList.value.filter(item => item.group_id === val).map(item => item.id)
	}
)

getOptions()
</script>

<style lang="scss" scoped></style>
