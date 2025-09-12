<template>
	<div class="flex-1">
		<div class="flex justify-end gap-12px mb-8px">
			<div>
				<bt-file-upload
					mode="button"
					button-type="primary"
					button-size="small"
					:accept="['html']"
					@change="handleFileUpload">
					{{ $t('market.template.uploadHtml') }}
				</bt-file-upload>
			</div>
			<n-button type="primary" ghost @click="handlePreview">
				{{ $t('common.actions.preview') }}
			</n-button>
		</div>
		<div class="h-400px">
			<bt-editor v-model:value="content" language="html"> </bt-editor>
		</div>
		<preview-modal />
	</div>
</template>

<script lang="ts" setup>
import { UploadFileInfo } from 'naive-ui'
import { useModal } from '@/hooks/modal/useModal'

import TemplatePreview from '@/views/market/template/components/TemplatePreview.vue'

const content = defineModel<string>('value')

const handleFileUpload = (file: UploadFileInfo) => {
	const reader = new FileReader()
	reader.onload = e => {
		content.value = e.target?.result as string
	}
	if (file.file) {
		reader.readAsText(file.file)
	}
}

const [PreviewModal, previewModalApi] = useModal({
	component: TemplatePreview,
})

const handlePreview = () => {
	previewModalApi.setState({ html: content.value })
	previewModalApi.open()
}
</script>

<style lang="scss" scoped></style>
