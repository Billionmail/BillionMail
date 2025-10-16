<template>
	<n-select v-model:value="value" :options="options" :multiple="true" max-tag-count="responsive">
		<template #action>
			<n-button block @click="handleManageTags">{{
				t('contacts.subscribers.tagSelect.manageTags')
			}}</n-button>
		</template>
	</n-select>
</template>

<script lang="tsx" setup>
import { SelectOption } from 'naive-ui'
import { isObject } from '@/utils'
import { getTagAll } from '../../tags/service'
import { Tag } from '../../tags/types'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const { groupId } = defineProps({
	groupId: {
		type: Number,
		default: 0,
	},
})

const value = defineModel<number[]>('value')

const tagList = ref<Tag[]>([])

const options = computed<SelectOption[]>(() => {
	return tagList.value
		.filter(item => (groupId === 0 ? true : groupId === item.group_id))
		.map(item => ({
			label: item.name,
			value: item.id,
		}))
})

const getOptions = async () => {
	const res = await getTagAll({})
	if (isObject<{ list: Tag[] }>(res)) {
		tagList.value = res.list
	}
}

getOptions()

const router = useRouter()

const handleManageTags = () => {
	router.push({
		path: '/contacts/tags',
		state: { group_id: groupId },
	})
}
</script>

<style lang="scss" scoped></style>
