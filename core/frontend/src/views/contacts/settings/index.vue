<template>
	<div class="p-24px">
		<div class="bt-title mb-12px!">
			{{ $t('layout.menu.contacts') }}
		</div>
		<n-breadcrumb class="mb-4px">
			<n-breadcrumb-item>
				<router-link to="/contacts/group">Group</router-link>
			</n-breadcrumb-item>
			<n-breadcrumb-item @click="onBack">{{ groupInfo?.name || '--' }}</n-breadcrumb-item>
			<n-breadcrumb-item>{{ $t('contacts.settings.title') }}</n-breadcrumb-item>
		</n-breadcrumb>
		<n-tabs v-model:value="activeTab" type="line">
			<n-tab-pane name="form" :tab="$t('contacts.settings.tabs.subscribeForm')">
				<subscribe-form />
			</n-tab-pane>
			<n-tab-pane name="subscribe" :tab="$t('contacts.settings.tabs.subscribeSettings')">
				<subscribe-settings />
			</n-tab-pane>
		</n-tabs>
	</div>
</template>

<script lang="ts" setup>
import { isObject } from '@/utils'
import { getGroupInfo } from '@/api/modules/contacts/group'
import { createContext } from './hooks/useContext'
import type { GroupInfo } from './types/base'

import SubscribeForm from './components/SubscribeForm.vue'
import SubscribeSettings from './components/SubscribeSettings.vue'

const route = useRoute()
const router = useRouter()

const id = computed(() => {
	return Number(route.params.id)
})

const activeTab = ref('form')

const groupInfo = ref<GroupInfo | null>(null)

const getInfo = async () => {
	const res = await getGroupInfo({ group_id: id.value })
	if (isObject<GroupInfo>(res)) {
		groupInfo.value = res
	}
}

const onBack = () => {
	router.back()
}

createContext({
	groupInfo,
	getInfo,
})

getInfo()
</script>

<style lang="scss" scoped></style>
