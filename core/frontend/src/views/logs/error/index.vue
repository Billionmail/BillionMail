<template>
	<div class="error-logs-container">
		<div class="logs-header">
			<n-button type="primary" @click="getLogs">{{ $t('common.actions.refresh') }}</n-button>
		</div>
		<div class="logs-content min-h-300px">
			<n-spin :show="loading">
				<bt-logs :code="content" height="100%" :scroll-to-bottom="true"></bt-logs>
			</n-spin>
		</div>
	</div>
</template>

<script lang="ts" setup>
import { isString } from '@/utils'
import { getErrorLogs } from './controller'

const content = ref('')
const loading = ref(false)

const getLogs = async () => {
	try {
		loading.value = true
		const res = await getErrorLogs()
		content.value = isString(res) ? res : ''
	} finally {
		loading.value = false
	}
}

getLogs()
</script>

<style lang="scss" scoped>
.error-logs-container {
	display: flex;
	flex-direction: column;
	height: calc(100vh - 200px); // 减去布局的 paddingTop 和页面 padding
	box-sizing: border-box;
}

.logs-header {
	flex-shrink: 0;
	margin-bottom: 16px;
}

.logs-content {
	flex: 1;
	min-height: 0; // 防止 flex 子元素溢出
	display: flex;
	flex-direction: column;

	:deep(.n-spin-container) {
		height: 100%;
		display: flex;
		flex-direction: column;
	}

	:deep(.code-container) {
		flex: 1;
		min-height: 0;
	}
}
</style>
