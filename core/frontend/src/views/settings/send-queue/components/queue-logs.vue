<template>
	<bt-modal v-model:show="show" :title="$t('overview.sendQueue.queueLogs.title')" :width="800" :footer="false">
		<n-spin :show="loading">
			<bt-logs height="520px" :code="content"></bt-logs>
		</n-spin>
	</bt-modal>
</template>

<script lang="ts" setup>
import { getSendQueueInfo } from '@/api/modules/overview'
import { isString } from '@/utils'

const show = ref(false)

const loading = ref(false)

const content = ref('')

const open = async (id: string) => {
	show.value = true
	loading.value = true
	content.value = ''
	try {
		const res = await getSendQueueInfo({ queue_id: id })
		if (isString(res)) {
			content.value = res
		}
	} finally {
		loading.value = false
	}
}

defineExpose({
	open,
})
</script>

<style lang="scss" scoped></style>
