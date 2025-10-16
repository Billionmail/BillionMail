<template>
	<div class="max-w-4xl mx-auto px-4 py-8">
		<SecuritySettings />
		<NetworkSettings />
		<SystemSettings />
	</div>
</template>

<script lang="ts" setup>
import { useSettingsStore } from '@/views/settings/common/store'

import SecuritySettings from './components/SecuritySettings.vue'
import NetworkSettings from './components/NetworkSettings.vue'
import SystemSettings from './components/SystemSettings.vue'

const settingsStore = useSettingsStore()

settingsStore.getCommonConfig()

onBeforeUnmount(() => {
	settingsStore.reset()
})
</script>
