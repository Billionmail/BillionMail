<template>
	<div class="content-wrapper">
		<n-card class="mb-5">
			<div class="page-tit">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:apps-fill text-6"></i>
					</div>
					<span class="tit-content">{{ $t('domain.edit.projectDetails.title') }}</span>
				</div>
			</div>
		</n-card>
		<n-card class="mb-5">
			<n-form>
				<n-form-item>
					<template #label><span class="form-label">{{
						$t('domain.edit.projectDetails.projectName')
					}}</span></template>
					<n-input v-model:value="project_name"></n-input>
				</n-form-item>
				<n-form-item>
					<template #label><span class="form-label">{{
						$t('domain.edit.projectDetails.description')
					}}</span></template>
					<n-input v-model:value="description" type="textarea" :rows="7"></n-input>
				</n-form-item>
			</n-form>
		</n-card>

		<n-card class="mb-5">
			<div class="page-tit mb-20px">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:earth-fill text-6"></i>
					</div>
					<span class="tit-content">{{ $t('domain.edit.projectDetails.brandLogos') }}</span>
				</div>
			</div>

			<div class="sub-tit">
				<span class="tit">{{ $t('domain.edit.projectDetails.logoSystem') }}</span>
				<span>{{ $t('domain.edit.projectDetails.logoSystemDesc') }}</span>
			</div>

			<div class="logo-operation">
				<div class="operation-item">
					<div class="operation-tit">{{ $t('domain.edit.projectDetails.primaryLogo') }}</div>
					<div class="operation-sub-tit">
						{{ $t('domain.edit.projectDetails.primaryLogoDesc') }}
					</div>
					<div class="logo-area" @click="choosePrimary">
						<div v-if="!primary_logo" class="upload-logo-placeholder">
							<i class="i-carbon:cloud-upload text-8"></i>
							<span>{{ $t('domain.edit.projectDetails.primaryLogo') }}</span>
						</div>
						<n-image v-else :src="primary_logo" height="100" width="150" object-fit="contain"
							preview-disabled>
							<template #error>
								<div class="w-100% h-100% flex justify-center items-center flex-col gap-1.25">
									<i class="i-mingcute:pic-line text-15"></i>
									<span>{{ $t('domain.edit.projectDetails.loadingFailed') }}</span>
								</div>
							</template>
						</n-image>
						<input v-show="false" ref="primaryUpload" type="file"
							@change="event => faviconChange(event, 'primary')" />
					</div>
				</div>
				<div class="operation-item">
					<div class="operation-tit">{{ $t('domain.edit.projectDetails.secondaryLogo') }}</div>
					<div class="operation-sub-tit">
						{{ $t('domain.edit.projectDetails.secondaryLogoDesc') }}
					</div>
					<div class="logo-area" @click="chooseSecondary">
						<div v-if="!secondary_logo" class="upload-logo-placeholder">
							<i class="i-carbon:cloud-upload text-8"></i>
							<span>{{ $t('domain.edit.projectDetails.primaryLogo') }}</span>
						</div>
						<n-image v-else :src="secondary_logo" height="100" width="150" object-fit="contain"
							preview-disabled>
							<template #error>
								<div class="w-100% h-100% flex justify-center items-center flex-col gap-1.25">
									<i class="i-mingcute:pic-line text-15"></i>
									<span>{{ $t('domain.edit.projectDetails.loadingFailed') }}</span>
								</div>
							</template>
						</n-image>
						<input v-show="false" ref="secondaryUpload" type="file"
							@change="event => faviconChange(event, 'secondary')" />
					</div>
				</div>
				<div class="operation-item">
					<div class="operation-tit">{{ $t('domain.edit.projectDetails.favicon') }}</div>
					<div class="operation-sub-tit">{{ $t('domain.edit.projectDetails.faviconDesc') }}</div>
					<div class="logo-area" @click="chooseFavicon">
						<div v-if="!favicon" class="upload-logo-placeholder">
							<i class="i-carbon:cloud-upload text-8"></i>
							<span>{{ $t('domain.edit.projectDetails.primaryLogo') }}</span>
						</div>
						<n-image v-else :src="favicon" height="40" width="60" object-fit="contain" preview-disabled>
							<template #error>
								<div class="w-100% h-100% flex justify-center items-center flex-col gap-1.25">
									<i class="i-mingcute:pic-line text-15"></i>
									<span>{{ $t('domain.edit.projectDetails.loadingFailed') }}</span>
								</div>
							</template>
						</n-image>
						<input v-show="false" ref="faviconUpload" type="file"
							@change="event => faviconChange(event, 'favicon')" />
					</div>
					<!-- <div class="operation-tools">
						<div class="tool-item">
							<i class="i-carbon:copy text-4"></i>
						</div>
						<div class="tool-item">
							<i class="i-carbon:overflow-menu-vertical text-4"></i>
						</div>
						<div class="tool-item">
							<i class="i-carbon:export text-4"></i>
						</div>
						<div class="tool-item">
							<i class="i-material-symbols:delete-outline text-4"></i>
						</div>
					</div> -->
				</div>
			</div>
		</n-card>

		<n-card>
			<div class="page-tit">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:earth-fill text-6"></i>
					</div>
					<span class="tit-content">{{ $t('domain.edit.projectDetails.knowledgeBase') }}</span>
				</div>

				<div class="right-tit">
					<n-button @click="knowledgeModalShow = true">{{
						$t('domain.edit.projectDetails.newFile')
					}}</n-button>
				</div>
			</div>

			<n-card v-for="(item, index) in knowledge_base" :key="index" class="mt-5"
				style="background-color: var(--color-radio-1)">
				<div class="knowledge-box">
					<div class="top-info">
						<div class="info-left">
							<span class="info-tit">{{ item.title }}</span>
							<span class="info-sub-tit">{{ formatTimeDifference(item.update_time) }} {{ $t('domain.edit.projectDetails.ago') }}</span>
						</div>
						<div class="info-right" @click="handleDelete(item)">
							<i class="i-material-symbols:delete-outline text-5"></i>
						</div>
					</div>
					<div class="operation">
						<n-button type="primary" ghost @click="openEditKnowledge(item)">{{
							$t('domain.edit.projectDetails.edit')
						}}</n-button>
						<n-button type="primary" ghost @click="previewKnowledgeBaseContent(item)">
							{{ $t('domain.edit.projectDetails.preview') }}
						</n-button>
					</div>
				</div>
			</n-card>
		</n-card>
	</div>

	<!-- Add knowledge base -->
	<n-modal v-model:show="knowledgeModalShow" preset="card" draggable :close-on-esc="false" :mask-closable="false"
		:title="$t('domain.edit.projectDetails.newKnowledgeFile')" class="w-150" :on-after-leave="closeKnowledgeModal">
		<n-form>
			<n-form-item :label="$t('domain.edit.projectDetails.fileName')">
				<n-input v-model:value="knowledgeTitle"></n-input>
			</n-form-item>
			<n-form-item label="Content">
				<n-input v-model:value="knowledgeContent" type="textarea" :rows="8"></n-input>
			</n-form-item>
		</n-form>

		<template #footer>
			<div class="flex justify-end gap-5">
				<n-button @click="closeKnowledgeModal">{{ $t('domain.edit.projectDetails.cancel') }}</n-button>
				<n-button type="primary" :disabled="!knowledgeTitle || !knowledgeContent"
					@click="createOrUpdateKnowledge">
					{{ $t('domain.edit.projectDetails.create') }}
				</n-button>
			</div>
		</template>
	</n-modal>

	<!-- Preview knowledge base -->
	<n-modal v-model:show="knowledgeBasePreview" preset="card" draggable :close-on-esc="false" :mask-closable="false"
		:title="knowledgeBasePreviewTit" class="w-180">
		<div class="preview-wrapper">
			<n-scrollbar style="max-height: 700px">
				<div v-html="mdRes"></div>
			</n-scrollbar>
		</div>
		<template #footer>
			<div class="flex justify-end">
				<n-button>{{ $t('domain.edit.projectDetails.close') }}</n-button>
			</div>
		</template>
	</n-modal>
</template>

<script setup lang="ts">
import mk from 'markdown-it'
import { confirm } from '@/utils'
import {
	getProjectDetail,
	createKnowledgeBase,
	closeKnowledgeModal,
	openEditKnowledge,
	updateKnowledgeBase,
	deleteKnowledgeBase,
	previewKnowledgeBaseContent,
	uploadImage,
} from '../controller/projectDetail.controller'
import { getEditDomainStoreData } from '../store'
import { KnowledgeBase } from '../dto'
const { t } = useI18n()
const {
	project_name,
	description,
	primary_logo,
	secondary_logo,
	favicon,
	knowledge_base,
	knowledgeModalShow,
	isEditKnowledge,
	knowledgeTitle,
	knowledgeContent,
	knowledge_base_content,
	knowledgeBasePreview,
	knowledgeBasePreviewTit,
} = getEditDomainStoreData()

const route = useRoute()

// const industryOptions = ref([
// 	{
// 		label: 'test',
// 		value: 'test',
// 	},
// ])

const domain = route.params.domain as string
const md = mk()
const mdRes = ref('')
const faviconUpload = ref()
const secondaryUpload = ref()
const primaryUpload = ref()

watch(knowledge_base_content, val => {
	mdRes.value = md.render(val)
})

getProjectDetail(domain)
/**
 * @description Create or update knowledge
 */
function createOrUpdateKnowledge() {
	if (isEditKnowledge.value) {
		updateKnowledgeBase(domain)
	} else {
		createKnowledgeBase(domain)
	}
}

/**
 * @description Delete knowledge base
 */
function handleDelete(knowledge: KnowledgeBase) {
	confirm({
		title: t('domain.edit.projectDetails.notice'),
		content: t("domain.edit.projectDetails.sureDel"),
		onConfirm() {
			deleteKnowledgeBase(domain, knowledge)
		},
	})
}

/**
 * @description Choose favicon file
 */
function chooseFavicon() {
	faviconUpload.value.click()
}

/**
 * @description Choose secondary file
 */
function chooseSecondary() {
	secondaryUpload.value.click()
}

/**
 * @description Choose primary file
 */
function choosePrimary() {
	primaryUpload.value.click()
}

/**
 * @description Favicon file change
 */
function faviconChange(event: Event, type: string) {
	const file = (event.target as HTMLInputElement).files![0]
	if (!file) return
	const reader = new FileReader()
	reader.onload = async function (event: ProgressEvent<FileReader>) {
		const base64String = event.target?.result as string
		if (type == 'favicon') {
			uploadImage(domain, base64String, file.name, 'favicon', 'favicon')
		}

		if (type == 'secondary') {
			uploadImage(domain, base64String, file.name, 'secondary logo', 'secondary logo')
		}

		if (type == 'primary') {
			uploadImage(domain, base64String, file.name, 'primary logo', 'primary logo')
		}
	}
	reader.readAsDataURL(file)
}

/**
 * @description Format time difference
 * @param timestamp 
 */
function formatTimeDifference(timestamp: number): string {
	const targetMs = timestamp * 1000;
	const nowMs = Date.now();
	const diffMs = targetMs - nowMs;

	const absDiffMs = Math.abs(diffMs);
	const days = Math.floor(absDiffMs / (24 * 60 * 60 * 1000));
	const hours = Math.floor((absDiffMs % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
	const minutes = Math.floor((absDiffMs % (60 * 60 * 1000)) / (60 * 1000));

	if( days === 0 && hours === 0 && minutes === 0) {
		return t("domain.edit.projectDetails.justNow");
	}else if (days === 0 && hours === 0) {
		return `${minutes}${t("domain.edit.projectDetails.minute")}`;
	} else if (days === 0 ) {
		return `${hours}${t("domain.edit.projectDetails.hour")} ${minutes}${t("domain.edit.projectDetails.minute")}`;
	}
	return `${days}${t("domain.edit.projectDetails.day")} ${hours}${t("domain.edit.projectDetails.hour")} ${minutes}${t("domain.edit.projectDetails.minute")}`;
}
</script>

<style scoped lang="scss">
@use '@/styles/index' as base;
@use './mixin.scss' as mixin;

.content-wrapper {
	@include mixin.content-wrapper;

	.page-tit {
		@include mixin.page-tit;
	}

	.sub-tit {
		@include base.col-flex-start;
		align-items: flex-start;
		gap: 10px;
		color: var(--color-text-2);
		margin-bottom: 40px;

		.tit {
			font-size: 14px;
			font-weight: bold;
		}
	}

	.logo-operation {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 20px;

		.operation-item {
			.operation-tit {
				margin-bottom: 5px;
				font-size: 14px;
				font-weight: bold;
			}

			.operation-sub-tit {
				margin-bottom: 15px;
			}

			.logo-area {
				width: 100%;
				height: 130px;
				border: 1px solid var(--color-border-1);
				border-radius: 16px;
				margin-bottom: 10px;
				@include base.row-flex;
				justify-content: center;
				align-items: center;

				.upload-logo-placeholder {
					@include base.col-flex-center;
					gap: 5px;
					height: 100%;
				}
			}

			.operation-tools {
				@include base.row-flex-start;
				gap: 10px;

				.tool-item {
					width: 34px;
					height: 34px;
					@include base.row-flex-center;
					background: var(--color-bg-1);
					border: 1px solid var(--color-border-1);
					border-radius: 5px;
					color: var(--color-text-2);
					cursor: pointer;

					&:hover {
						background: var(--color-bg-4);
					}
				}
			}
		}
	}

	.form-label {
		@include mixin.form-label;
	}

	.knowledge-box {
		@include base.col-flex;
		justify-content: flex-start;
		align-items: flex-start;

		.top-info {
			width: 100%;
			@include base.row-flex;
			justify-content: space-between;
			align-items: flex-start;
			margin-bottom: 20px;

			.info-left {
				@include base.col-flex;
				justify-content: flex-start;
				align-items: flex-start;

				.info-tit {
					font-size: 16px;
					font-weight: bold;
				}
			}

			.info-right {
				@include base.row-flex-center;
				align-items: center;
				padding: 5px;
				cursor: pointer;
				transition: 0.15s all ease-in-out;

				&:hover {
					background: var(--color-border-2);
				}
			}
		}

		.operation {
			@include base.row-flex-start;
			gap: 15px;
		}
	}
}
</style>

<style>
.preview-wrapper {
	max-height: 700px;

	img {
		max-width: 100% !important;
	}
}
</style>
