<template>
	<div class="subscribe-form-container">
		<!-- 分离订阅页面部分 -->
		<div class="section">
			<h3 class="section-title">
				{{ $t('contacts.settings.subscribeForm.separateSubscriptionPage.title') }}
			</h3>
			<p class="section-description">
				{{ $t('contacts.settings.subscribeForm.separateSubscriptionPage.description') }}
			</p>
			<form-code :value="subscriptionUrl"></form-code>
		</div>

		<!-- 可嵌入表单部分 -->
		<div class="section">
			<h3 class="section-title">
				{{ $t('contacts.settings.subscribeForm.embeddableForm.title') }}
			</h3>
			<p class="section-description">
				{{ $t('contacts.settings.subscribeForm.embeddableForm.description') }}
			</p>
			<form-code :value="embedCode"></form-code>
		</div>
	</div>
</template>

<script setup lang="ts">
import { useContext } from '../hooks/useContext'
import FormCode from './Code.vue'

// 订阅页面URL
const subscriptionUrl = ref('')

// 嵌入代码
const embedCode = ref(``)

const { groupInfo } = useContext()

watchEffect(() => {
	if (groupInfo.value) {
		subscriptionUrl.value = groupInfo.value.subscribe_link
		embedCode.value = groupInfo.value.subscribe_form
	}
})
</script>

<style scoped>
.subscribe-form-container {
	max-width: 800px;
}

.section {
	margin-bottom: 32px;
}

.section-title {
	margin-bottom: 12px;
	font-size: 14px;
	font-weight: 600;
	color: var(--color-text-1);
}

.section-description {
	margin-bottom: 12px;
	color: var(--color-text-2);
}
</style>
