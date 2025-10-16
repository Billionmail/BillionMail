<template>
	<div class="content-wrapper">
		<n-card class="mb-5">
			<div class="page-tit" style="margin: 0">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:apps-fill text-6"></i>
					</div>
					<span class="tit-content"> Typography </span>
				</div>
			</div>
		</n-card>

		<n-card class="mb-5">
			<n-form>
				<n-form-item>
					<template #label><span class="form-label">Heading Font</span></template>
					<n-input v-model:value="heading_font"></n-input>
				</n-form-item>

				<n-card class="form-desc">
					<div class="container">
						<div class="form-label">Preview:</div>
						<div class="desc" :style="{ fontFamily: heading_font }">
							The quick brown fox jumps over the lazy dog
						</div>
					</div>
				</n-card>
			</n-form>
		</n-card>

		<n-card class="mb-5">
			<n-form>
				<n-form-item>
					<template #label><span class="form-label">Body Font</span></template>
					<n-input v-model:value="body_font"></n-input>
				</n-form-item>

				<n-card class="form-desc">
					<div class="container">
						<div class="form-label">Preview:</div>
						<div class="desc" :style="{ fontFamily: body_font }">
							The quick brown fox jumps over the lazy dog
						</div>
					</div>
				</n-card>
			</n-form>
		</n-card>

		<n-card>
			<div class="attention">
				<div class="attention-tit">Typography Guidelines:</div>
				<div class="attention-item">Use web-safe fonts for better compatibility</div>
				<div class="attention-item">Always include fallback fonts for better performance</div>
			</div>
		</n-card>
	</div>
</template>

<script setup lang="ts">
// import { updateTypography } from '../controller/typography.controller'
import { getEditDomainStoreData } from '../store'

const { heading_font, body_font } = getEditDomainStoreData()

// const route = useRoute()
// const domain = route.params.domain as string
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
