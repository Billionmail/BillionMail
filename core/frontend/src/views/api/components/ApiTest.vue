<template>
	<modal title="Test API" width="720" :footer="false">
		<bt-form ref="formRef" :model="form" :rules="rules" class="pt-12px">
			<n-form-item :label="$t('market.task.edit.testEmail')" path="recipient">
				<div class="flex-1 mr-10px">
					<n-input
						v-model:value="form.recipient"
						:placeholder="$t('market.task.edit.testEmailPlaceholder')">
					</n-input>
				</div>
			</n-form-item>
			<n-form-item label="Command">
				<bt-code :code="commandRef" language="bash"></bt-code>
			</n-form-item>
		</bt-form>
	</modal>
</template>

<script lang="ts" setup>
import { FormRules } from 'naive-ui'
import { useModal } from '@/hooks/modal/useModal'
import type { Api } from '../types/base'

const { t } = useI18n()

const command = ref(``)

const commandRef = computed(() => {
	return command.value.replaceAll('$email', form.recipient)
})

const form = reactive({
	recipient: '',
})

const rules: FormRules = {
	recipient: {
		required: true,
		message: t('market.task.edit.testEmailPlaceholder'),
	},
}

const resetForm = () => {
	form.recipient = ''
}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ row: Api }>()
			const { row } = state
			if (row) {
				command.value = `curl -k -X POST '${row.server_addresser}' \\
-H 'X-API-Key: ${row.api_key}' \\
-H 'Content-Type: application/json' \\
-d '{
	"recipient": "$email"
}'`
			}
		} else {
			resetForm()
		}
	},
})
</script>

<style lang="scss" scoped></style>
