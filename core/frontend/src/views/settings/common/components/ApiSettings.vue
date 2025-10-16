<template>
	<div>
		<div class="flex items-center mb-12px">
			<span class="font-bold text-basic text-14px">{{ $t('settings.common.api.title') }}</span>
			<n-button class="ml-8px" text type="primary" @click="handleClickHelp">
				{{ $t('common.actions.help') }}
			</n-button>
		</div>

		<div class="flex items-center mb-16px">
			<n-switch :value="apiInfo.api_doc_enabled" @update:value="onUpdateEnabled"> </n-switch>
			<span class="ml-8px text-desc">{{ $t('settings.common.api.enableApi') }}</span>
		</div>

		<div class="grid grid-cols-1 md:grid-cols-2 gap-16px mb-16px">
			<div>
				<n-input :value="apiInfo.api_doc_url" readonly></n-input>
				<p class="mt-1 text-xs text-desc">{{ $t('settings.common.api.apiDocUrl') }}</p>
			</div>
			<div>
				<n-input v-model:value="apiInfo.swagger_url" readonly> </n-input>
				<p class="mt-1 text-xs text-desc">{{ $t('settings.common.api.swaggerUrl') }}</p>
			</div>
		</div>

		<div>
			<label class="block text-sm font-medium mb-2"> {{ $t('settings.common.api.token') }} </label>
			<n-input
				v-model:value="apiInfo.api_token"
				type="textarea"
				:rows="5"
				:readonly="true"
				class="font-mono text-sm">
			</n-input>
		</div>
	</div>
</template>

<script lang="tsx" setup>
import { confirm } from '@/utils'
import { setApiDocEnabled } from '@/api/modules/settings/common'
import { getSettingsStore } from '../store'

const { t } = useI18n()

const { apiInfo, getCommonConfig } = getSettingsStore()

const onUpdateEnabled = (val: boolean) => {
	confirm({
		title: val ? t('settings.common.api.confirm.enable') : t('settings.common.api.confirm.disable'),
		content: val
			? t('settings.common.api.confirm.enableContent')
			: t('settings.common.api.confirm.disableContent'),
		onConfirm: async () => {
			await setApiDocEnabled({ api_doc_enabled: val })
			getCommonConfig()
		},
	})
}

const handleClickHelp = () => {
	window.open('https://billionmail.com/start/api_usage_guide.html')
}
</script>

<style lang="scss" scoped></style>
