<template>
	<div>
		<n-form-item ref="formItemRef" :label="$t('settings.common.proxy.title')" path="username">
			<div class="flex-1 grid grid-cols-1 md:grid-cols-2 gap-4">
				<div>
					<n-input :value="currentProxy" readonly />
					<p class="mt-1 text-xs text-desc">
						{{ $t('settings.common.proxy.description') }}
					</p>
				</div>
				<div>
					<n-input v-model:value="domain" :placeholder="$t('settings.common.proxy.placeholder')">
					</n-input>
					<p class="mt-1 text-xs text-desc">{{ $t('settings.common.proxy.formatTip') }}</p>
				</div>
			</div>
		</n-form-item>
		<div>
			<n-button type="primary" :disabled="!domain" @click="handleSubmit">
				{{ $t('settings.common.confirm') }}
			</n-button>
			<n-button class="ml-12px" @click="handleReset">
				{{ $t('settings.common.proxy.reset') }}
			</n-button>
		</div>
	</div>
</template>

<script lang="ts" setup>
import { getSettingsStore } from '@/views/settings/common/store'
import { clearReverseProxyDomain, setReverseProxyDomain } from '@/api/modules/settings/common'
import { confirm } from '@/utils'

const { t } = useI18n()

const { currentProxy, getCommonConfig } = getSettingsStore()

const domain = ref('')

const handleSubmit = async () => {
	await setReverseProxyDomain({ domain: domain.value })
	getCommonConfig()
	domain.value = ''
}

const handleReset = async () => {
	confirm({
		title: t('settings.common.proxy.resetConfirm.title'),
		content: t('settings.common.proxy.resetConfirm.content'),
		onConfirm: async () => {
			await clearReverseProxyDomain()
			getCommonConfig()
		},
	})
}
</script>
