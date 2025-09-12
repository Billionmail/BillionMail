<template>
	<n-modal
		v-model:show="show"
		preset="card"
		:close-on-esc="false"
		:mask-closable="false"
		draggable
		class="w-150"
		title="Add Provider">
		<n-form ref="addProviderFormDataRef" :model="addProviderFormData" :rules="rules">
			<n-form-item :label="$t('settings.aiModel.supplierTitle')" path="supplierTitle">
				<n-input v-model:value="addProviderFormData.supplierTitle"></n-input>
			</n-form-item>
			<n-form-item :label="$t('settings.aiModel.supplierName')" path="supplierName">
				<n-input v-model:value="addProviderFormData.supplierName"></n-input>
			</n-form-item>
			<n-form-item label="BaseURL" path="baseUrl">
				<n-input v-model:value="addProviderFormData.baseUrl"></n-input>
			</n-form-item>
			<n-form-item label="ApiKey" path="apiKey">
				<n-input v-model:value="addProviderFormData.apiKey"></n-input>
			</n-form-item>
		</n-form>
		<template #footer>
			<div class="flex justify-end gap-5">
				<n-button>Cancel</n-button>
				<n-button type="primary" @click="confirmAddProvider(store)">Confirm</n-button>
			</div>
		</template>
	</n-modal>
</template>

<script setup lang="ts">
import { confirmAddProvider } from '../controller'
import { ModelStore } from '../dto'
const store = inject<ModelStore>('modelStore')!
const { addProviderFormData, addProviderFormDataRef } = store
const show = ref(false)
const rules = {
	supplierTitle: [{ required: true, message: 'supplierTitle is required', trigger: 'blur' }],
	supplierName: [{ required: true, message: 'supplierName is required', trigger: 'blur' }],
	baseUrl: [{ required: true, message: 'baseUrl is required', trigger: 'blur' }],
	apiKey: [{ required: true, message: 'apiKey is required', trigger: 'blur' }],
}

/**
 * @description Open modal
 */
function open() {
	show.value = true
}

/**
 * @description Close modal
 */
function close() {
	show.value = false
}

defineExpose({
	open,
	close,
})
</script>

<style scoped></style>
