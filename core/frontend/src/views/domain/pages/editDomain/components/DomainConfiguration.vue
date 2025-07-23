<template>
	<div class="content-wrapper">
		<div>
			<n-card>
				<div class="page-tit mb-5">
					<div class="left-tit">
						<div class="back-tool">
							<i class="i-cuida:mail-outline text-7"></i>
						</div>
						<span class="tit-content">{{ $t('domain.edit.domainConfiguration.title') }}</span>
					</div>
				</div>
				<!-- form data -->
				<n-form>
					<n-form-item>
						<template #label><span class="form-label">{{
							$t('domain.edit.domainConfiguration.domain')
						}}</span></template>
						<n-input v-model:value="domainTit" @input="syncToUrl"></n-input>
					</n-form-item>
					<n-form-item label="">
						<template #label><span class="form-label">{{
							$t('domain.edit.domainConfiguration.domainQuota')
						}}</span></template>
						<div class="flex justify-between gap-5 items-center w-100%">
							<n-input v-model:value="quota"></n-input>
							<n-select v-model:value="unit" :options="uinitOptions" class="w-20"></n-select>
						</div>
					</n-form-item>
					<n-form-item>
						<template #label><span class="form-label">{{
							$t('domain.edit.domainConfiguration.mailboxCount')
						}}</span></template>
						<n-input-number v-model:value="mailboxes" :show-button="false"></n-input-number>
					</n-form-item>
					<n-form-item>
						<template #label><span class="form-label">{{
							$t('domain.edit.domainConfiguration.catchAll')
						}}</span></template>
						<n-input v-model:value="catch_email"></n-input>
					</n-form-item>
				</n-form>
			</n-card>

			<n-card v-if="createdBrandInfo" class="mt-5">
				<div class="page-tit mb-5">
					<div class="left-tit">
						<div class="back-tool">
							<i class="i-cuida:mail-outline text-7"></i>
						</div>
						<span class="tit-content">{{ $t("domain.edit.domainConfiguration.brandInfo") }}</span>
					</div>
					<div class="right-tit">
						<n-switch v-model:value="brandInfo" @update:value="switchBrandInfo"></n-switch>
					</div>
				</div>

				<div class="w-100% flex flex-col gap-2.5">
					<div v-for="(_, index) in urls" :key="index" class="flex justify-start items-center gap-2.5">
						<n-input v-model:value="urls[index]" :placeholder="$t('domain.form.urlsPlacement')"
							:disabled="!supplierStatus" readonly>
						</n-input>
						<div v-if="index != 0" class="close" @click="removeUrl(index)">
							<i class="i-material-symbols:close-rounded text-5"></i>
						</div>
					</div>
				</div>
			</n-card>

			<n-card v-else class="mt-5">
				<div class="fw-bold text-4 mb-5 text-[#777]">{{ $t("domain.edit.domainConfiguration.noBrandInfo") }}</div>
				<n-alert v-if="!supplierStatus" type="warning" class="mb-15px" :show-icon="false">
					<div class="w-100% flex justify-between items-center">
						<span class="mr-5">{{
							$t('domain.edit.domainConfiguration.aiIntegrationWarning')
						}}</span>
						<n-button type="primary" @click="jumpToAiSettings">{{
							$t('domain.edit.domainConfiguration.integrateImmediately')
						}}</n-button>
					</div>
				</n-alert>
				<div class="text-[#777]">
					{{ $t('domain.edit.domainConfiguration.aiDescription') }}
				</div>
				<bt-tips style="margin-bottom: 15px">
					<li>{{ $t('domain.edit.domainConfiguration.features.extractBrand') }}</li>
					<li>{{ $t('domain.edit.domainConfiguration.features.analyzeStructure') }}</li>
					<li>{{ $t('domain.edit.domainConfiguration.features.importContent') }}</li>
					<li>{{ $t('domain.edit.domainConfiguration.features.customLogo') }}</li>
				</bt-tips>
				<n-form-item :label="$t('domain.edit.domainConfiguration.specifyDomain')">
					<div class="w-100% flex flex-col gap-2.5">
						<div v-for="(_, index) in urls" :key="index" class="flex justify-start items-center gap-2.5">
							<n-input v-model:value="urls[index]" :placeholder="$t('domain.form.urlsPlacement')"
								:disabled="!supplierStatus">
							</n-input>
							<div v-if="index != 0" class="close" @click="removeUrl(index)">
								<i class="i-material-symbols:close-rounded text-5"></i>
							</div>
						</div>
						<!-- <div class="text-[#777]">{{ $t("domain.form.maxUrl") }}</div> -->
						<!-- <n-button type="primary" :disabled="!supplierStatus" ghost @click="addUrl">
							<template #icon>
								<i class="i-material-symbols:add-circle-outline"></i>
							</template>
							{{ $t('domain.edit.domainConfiguration.addMoreUrls') }}
						</n-button> -->
					</div>
				</n-form-item>
				<n-button type="primary" class="w-100%" @click="createBrandInfo">{{ $t("domain.edit.domainConfiguration.createNow") }}</n-button>
			</n-card>
		</div>
	</div>

	<!-- Wait for init brand info -->
	<WaitAndCheckDomainStatus ref="waitAndCheckDomainStatusRef" />
</template>

<script setup lang="ts">
import WaitAndCheckDomainStatus from '@/views/domain/components/WaitAndCheckDomainStatus.vue'
import {
	checkAiConfiguration,
} from '@/api/modules/domain'
import { getDomainDetail, syncToUrl, removeUrl, createBrandInfo,switchBrandInfo } from '../controller/domainConfiguration.controller'
import { getEditDomainStoreData } from '../store'
const router = useRouter()
const supplierStatus = ref(false)
const { domainTit, quota, unit, mailboxes, catch_email, urls, brandInfo, createdBrandInfo, waitAndCheckDomainStatusRef } = getEditDomainStoreData()
const route = useRoute()
const domain = route.params.domain as any
const uinitOptions = ref([
	{
		label: 'B',
		value: 'B',
	},
	{
		label: 'KB',
		value: 'KB',
	},
	{
		label: 'MB',
		value: 'MB',
	},
	{
		label: 'GB',
		value: 'GB',
	},
	{
		label: 'TB',
		value: 'TB',
	},
])

getDomainDetail(domain)
/**
 * @description Check AI configuration
 */
async function checkAiConfig() {
	const res = await checkAiConfiguration() as Record<string, any>
	if (res) {
		supplierStatus.value = res.is_configured
	}
}
checkAiConfig()

/**
 * @description Add url to urls
 */
// function addUrl() {
// 	urls.value.push('')
// }

/**
 * @description Jump to AI settings page
 */
function jumpToAiSettings(){
	router.push({
		name: "AiModel"
	})
}
</script>

<style scoped lang="scss">
@use '@/styles/index' as base;
@use './mixin.scss' as mixin;

.content-wrapper {
	@include mixin.content-wrapper;

	// title
	.page-tit {
		@include mixin.page-tit;
	}

	.form-label {
		@include mixin.form-label;
	}

	// Switch settings
	.switch-settings {
		@mixin settings-label {
			font-size: 14px;
			font-weight: bold;
		}

		.switch-item {
			@include base.row-flex;
			justify-content: space-between;
			margin-bottom: 15px;

			.label {
				color: var(--color-text-2);
				@include settings-label();
			}
		}
	}

	.close {
		@include mixin.operation-close;
	}
}
</style>
