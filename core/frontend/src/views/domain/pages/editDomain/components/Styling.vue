<template>
	<div class="content-wrapper">
		<n-card class="mb-5">
			<div class="page-tit mb-5">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:apps-fill text-6"></i>
					</div>
					<span class="tit-content"> {{ $t("domain.edit.styling.colorPalette") }} </span>
				</div>
			</div>
			<n-form>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.accentColor") }}</span></template>
					<div class="flex justify-between gap-2.5 w-100%">
						<n-color-picker
							v-model:value="accent_color"
							style="width: 50px"
							:modes="['hex', 'rgb', 'hsl', 'hsv']"
							:render-label="colorRenderLabel"></n-color-picker>
						<n-input v-model:value="accent_color"></n-input>
					</div>
				</n-form-item>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.textColor") }}</span></template>
					<div class="flex justify-between gap-2.5 w-100%">
						<n-color-picker
							v-model:value="text_color"
							style="width: 50px"
							:modes="['hex', 'rgb', 'hsl', 'hsv']"
							:render-label="colorRenderLabel"></n-color-picker>
						<n-input v-model:value="text_color"></n-input>
					</div>
				</n-form-item>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.pageBackground") }}</span></template>
					<div class="flex justify-between gap-2.5 w-100%">
						<n-color-picker
							v-model:value="page_background"
							style="width: 50px"
							:modes="['hex', 'rgb', 'hsl', 'hsv']"
							:render-label="colorRenderLabel"></n-color-picker>
						<n-input v-model:value="page_background"></n-input>
					</div>
				</n-form-item>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.containerBackground") }}</span></template>
					<div class="flex justify-between gap-2.5 w-100%">
						<n-color-picker
							v-model:value="container_background"
							style="width: 50px"
							:modes="['hex', 'rgb', 'hsl', 'hsv']"
							:render-label="colorRenderLabel"></n-color-picker>
						<n-input v-model:value="container_background"></n-input>
					</div>
				</n-form-item>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.linkFooterColor") }}</span></template>
					<div class="flex justify-between gap-2.5 w-100%">
						<n-color-picker
							v-model:value="link_footer_color"
							style="width: 50px"
							:modes="['hex', 'rgb', 'hsl', 'hsv']"
							:render-label="colorRenderLabel"></n-color-picker>
						<n-input v-model:value="link_footer_color"></n-input>
					</div>
				</n-form-item>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.linkSocialColor") }}</span></template>
					<div class="flex justify-between gap-2.5 w-100%">
						<n-color-picker
							v-model:value="link_social_color"
							style="width: 50px"
							:modes="['hex', 'rgb', 'hsl', 'hsv']"
							:render-label="colorRenderLabel"></n-color-picker>
						<n-input v-model:value="link_social_color"></n-input>
					</div>
				</n-form-item>
			</n-form>
		</n-card>

		<n-card class="mb-5">
			<div class="page-tit mb-5">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:apps-fill text-6"></i>
					</div>
					<span class="tit-content">{{ $t("domain.edit.styling.typography") }} </span>
				</div>
			</div>
			<n-form>
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.headingFont") }}</span></template>
					<n-input v-model:value="heading_font"></n-input>
				</n-form-item>

				<n-card class="form-desc">
					<div class="container">
						<div class="form-label">{{ $t("domain.edit.styling.preview") }}</div>
						<div class="desc" :style="{ fontFamily: heading_font }">
							{{ $t("domain.edit.styling.previewText") }}
						</div>
					</div>
				</n-card>
			</n-form>

			<n-form class="mt-5">
				<n-form-item>
					<template #label><span class="form-label">{{ $t("domain.edit.styling.bodyFont") }}</span></template>
					<n-input v-model:value="body_font"></n-input>
				</n-form-item>

				<n-card class="form-desc">
					<div class="container">
						<div class="form-label">{{ $t("domain.edit.styling.preview") }}</div>
						<div class="desc" :style="{ fontFamily: body_font }">
							{{ $t("domain.edit.styling.previewText") }}
						</div>
					</div>
				</n-card>
			</n-form>
		</n-card>

		<n-card>
			<div class="attention">
				<div class="attention-tit">{{ $t("domain.edit.styling.typographyGuidelines") }}</div>
				<div class="attention-item">{{ $t("domain.edit.styling.webSafeFonts") }}</div>
				<div class="attention-item">{{ $t("domain.edit.styling.fallbackFonts") }}</div>
			</div>
		</n-card>
	</div>
</template>

<script setup lang="tsx">
import { getStylingInfo } from '../controller/styling.controller'
import { getEditDomainStoreData } from '../store'
const {
	accent_color,
	text_color,
	link_footer_color,
	link_social_color,
	page_background,
	container_background,
	heading_font,
	body_font,
} = getEditDomainStoreData()
const route = useRoute()
const domain = route.params.domain as string
getStylingInfo(domain)

function colorRenderLabel() {
	return ''
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

	.form-label {
		@include mixin.form-label;
	}

	.sub-tit {
		color: var(--color-text-1);
	}

	.form-desc {
		border: 1px solid var(--color-border-1);

		.container {
			@include base.col-flex-start;
			align-items: flex-start;
			gap: 10px;

			.desc {
				color: var(--color-text-1);
				font-size: 14px;
			}
		}
	}

	.attention {
		.attention-tit {
			margin-bottom: 10px;
		}

		.attention-item {
			padding-left: 10px;
			position: relative;

			&::before {
				content: '';
				display: block;
				width: 4px;
				height: 4px;
				background: var(--color-text-2);
				border-radius: 50%;
				position: absolute;
				left: 0;
				top: 7px;
			}
		}
	}
}
</style>
