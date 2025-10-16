<template>
	<div class="content-wrapper">
		<n-card class="mb-5">
			<div class="page-tit" style="margin: 0">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:apps-fill text-6"></i>
					</div>
					<span class="tit-content"> {{ $t("domain.edit.footerSettings.title") }} </span>
				</div>
			</div>
		</n-card>

		<n-card>
			<div class="page-tit mb-5">
				<div class="left-tit">
					<span class="tit-content"> {{ $t("domain.edit.footerSettings.additionalContent") }} </span>
				</div>
			</div>

			<n-form>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.footerSettings.copyrightText") }}</span></template>
					<n-input v-model:value="copyright_text"></n-input>
				</n-form-item>
				<!-- <n-form-item>
					<template #label><span class="form-label">Disclaimer</span></template>
					<n-input v-model:value="disclaimer" type="textarea" :rows="8"></n-input>
				</n-form-item> -->
			</n-form>
		</n-card>
	</div>
</template>

<script setup lang="ts">
import { getFootersettingsInfo } from '../controller/footerSettings.controller'
import { getEditDomainStoreData } from '../store'

const { copyright_text } = getEditDomainStoreData()
const route = useRoute()
const domain = route.params.domain as string
getFootersettingsInfo(domain)
</script>

<style scoped lang="scss">
@use '@/styles/index' as base;
@use './mixin.scss' as mixin;

.content-wrapper {
	@include mixin.content-wrapper;

	.page-tit {
		@include mixin.page-tit;
	}

	.form-label {
		@include mixin.form-label;
	}
}
</style>
