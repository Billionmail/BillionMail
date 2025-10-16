<template>
	<modal :title="$t('market.task.detail.title')" :width="600" :footer="false">
		<n-descriptions
			v-if="row"
			label-placement="left"
			:bordered="true"
			:column="1"
			:label-style="{ width: '180px' }">
			<n-descriptions-item :label="$t('market.task.detail.displayName')">
				{{ row.full_name }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.detail.sender')">
				{{ row.addresser }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.detail.subject')">
				{{ row.subject }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.detail.groups')">
				{{ row.group_name }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.edit.tags')">
				<n-flex>
					<n-tag v-for="item of row.tags" :key="item.id" size="small">{{ item.name }}</n-tag>
				</n-flex>
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.edit.tagLogic')">
				{{ row.tag_logic }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.detail.sendTime')">
				{{ formatTime(row.start_time) }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.detail.unsubscribeLink')">
				{{ row.unsubscribe === 1 ? $t('market.task.detail.yes') : $t('market.task.detail.no') }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.detail.threads')">
				{{ row.threads === 0 ? $t('market.task.detail.auto') : row.threads }}
			</n-descriptions-item>
			<n-descriptions-item :label="$t('market.task.detail.remark')">
				{{ row.remark || '--' }}
			</n-descriptions-item>
		</n-descriptions>
	</modal>
</template>

<script lang="ts" setup>
import { formatTime } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import type { Task } from '../interface'

const row = ref<Task | null>(null)

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ row: Task }>()
			row.value = state.row
		}
	},
})
</script>

<style lang="scss" scoped></style>
