<template>
	<modal :title="$t('contacts.suspend.scanLogs.title')" width="820" :footer="false">
		<div class="pt-12px mb-8px">
			<n-button type="primary" @click="getLogs(true)">
				{{ $t('common.actions.refresh') }}
			</n-button>
		</div>
		<n-spin :show="loading">
			<bt-logs height="480px" :code="content"></bt-logs>
		</n-spin>
	</modal>
</template>

<script lang="ts" setup>
import { isString } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { getScanLogs } from '@/api/modules/contacts/suspend'

const { t } = useI18n()

const loading = ref(false)

const content = ref(t('contacts.suspend.scanLogs.none'))

let timer: number | null = null

const isAutoRefreshing = ref(false)

const retryCount = ref(0)

const MAX_RETRIES = 3

const getLogs = async (showLoading = false) => {
	try {
		if (showLoading) {
			loading.value = true
		}
		const res = await getScanLogs()
		if (isString(res)) {
			content.value = res

			// 成功获取后重置重试计数
			retryCount.value = 0

			// 检查是否包含"Check finished"或"扫描完成"文本
			if (content.value.includes('Check finished') || content.value.includes('扫描完成')) {
				stopAutoRefresh()
			} else if (isAutoRefreshing.value) {
				// 如果需要继续自动刷新，设置下一次执行的定时器
				scheduleNextUpdate()
			}
		} else {
			handleError()
		}
	} finally {
		if (showLoading) {
			loading.value = false
		}
	}
}

const handleError = () => {
	// 错误计数，达到最大重试次数后停止自动刷新
	retryCount.value++

	if (retryCount.value >= MAX_RETRIES) {
		stopAutoRefresh()
	} else if (isAutoRefreshing.value) {
		// 如果未达到最大重试次数，继续尝试
		scheduleNextUpdate()
	}
}

// 安排下一次更新
const scheduleNextUpdate = () => {
	if (isAutoRefreshing.value) {
		// 清除可能存在的定时器
		if (timer !== null) {
			clearTimeout(timer)
		}

		// 设置下一次执行的定时器
		timer = window.setTimeout(() => {
			getLogs(false)
		}, 1000)
	}
}

// 停止自动刷新
const stopAutoRefresh = () => {
	if (timer !== null) {
		clearTimeout(timer)
		timer = null
	}
	isAutoRefreshing.value = false
}

const [Modal] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			getLogs(true)
		} else {
			content.value = t('contacts.suspend.scanLogs.none')
			stopAutoRefresh()
		}
	},
})
</script>

<style lang="scss" scoped></style>
