<template>
	<modal :title="$t('market.template.add.title')" width="480">
		<div class="pt-12px">
			<bt-form ref="formRef" :model="form" :rules="rules">
				<n-form-item :label="$t('market.template.name')" path="temp_name">
					<n-input
						v-model:value="form.temp_name"
						:placeholder="$t('market.template.add.namePlaceholder')">
					</n-input>
				</n-form-item>
				<n-form-item :label="$t('market.template.file')" path="mode">
					<div class="flex-1">
						<n-radio-group v-model:value="form.add_type">
							<n-radio-button :value="0">{{ $t('market.template.uploadHtml') }}</n-radio-button>
						</n-radio-group>
						<div v-if="form.add_type === 0" class="mt-16px">
							<bt-file-upload :is-upload="false" :accept="['html']" @change="handleChangeFile">
							</bt-file-upload>
						</div>
					</div>
				</n-form-item>
			</bt-form>
		</div>
	</modal>
</template>

<script lang="ts" setup>
import { FormRules, UploadFileInfo } from 'naive-ui'
import { isEmpty } from 'lodash-es'
import { formatTime, Message } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
// import { addTemplate } from '@/api/modules/market/template'

const { t } = useI18n()

const formRef = useTemplateRef('formRef')

const form = reactive({
	temp_name: '',
	add_type: 0,
	content: '',
	render: '',
	file_data: '',
})

const rules: FormRules = {
	temp_name: {
		required: true,
		trigger: ['input', 'blur'],
		message: t('market.template.add.validation.nameRequired'),
	},
}

const handleChangeFile = (file: UploadFileInfo) => {
	const reader = new FileReader()
	reader.onload = e => {
		form.file_data = e.target?.result as string
	}
	if (file.file) {
		reader.readAsText(file.file)
	}
}

const validateForm = async () => {
	await formRef.value?.validate()
	if (form.add_type === 2 && isEmpty(form.file_data)) {
		Message.error(t('market.template.add.validation.uploadRequired'))
		return Promise.reject()
	}
}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			form.temp_name = `template_${formatTime(new Date(), 'yyyyMMddHHmmss')}`
			form.add_type = 0
			form.content = ''
			form.render = ''
			form.file_data = ''
		}
	},
	onConfirm: async () => {
		await validateForm()
		// await addTemplate(toRaw(form))
		const state = modalApi.getState<{ refresh: () => void }>()
		state?.refresh()
	},
})
</script>

<style lang="scss" scoped>
.drag-area {
	border: 1px dashed #d9d9d9;
	border-radius: 2px;
	min-height: 300px;
	display: flex;
	justify-content: center;
	align-items: center;
	transition: border-color 0.3s;

	&:hover {
		border-color: #1890ff;
	}

	.drag-placeholder {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		color: #999;
	}
}
</style>
