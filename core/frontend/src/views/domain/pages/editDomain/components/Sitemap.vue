<template>
	<div class="content-wrapper">
		<n-card class="mb-5">
			<div class="page-tit">
				<div class="left-tit">
					<div class="back-tool">
						<i class="i-ri:apps-fill text-6"></i>
					</div>
					<span class="tit-content"> {{ $t("domain.edit.sitemap.title") }} </span>
				</div>
			</div>
		</n-card>

		<n-card>
			<div class="mb-5">
				<n-button type="primary" @click="handleAdd">{{ $t("domain.edit.sitemap.addLink") }}</n-button>
			</div>
			<div v-for="(item, index) in sitemap" :key="index" class="mb-2.5">
				<div class="inline-form-items">
					<n-input v-model:value="item.title" class="name"></n-input>
					<n-input v-model:value="item.uri_path" class="url"></n-input>
					<div class="operation close" @click="handleRemove(item, index)">
						<i class="i-material-symbols:close-rounded text-5"></i>
					</div>
					<div :class="[
						'operation',
						{ save: item.title && item.uri_path },
						{ disabled: !item.title || !item.uri_path },
					]" @click="handleSave(item, index)">
						<i class="i-mingcute:save-2-line text-5"></i>
					</div>
				</div>
			</div>
		</n-card>
	</div>
</template>

<script setup lang="ts">
	import { getSitemapInfo, addSitemapInfo, removeSiteMapInfo } from '../controller/sitemap.controller'
	import { getEditDomainStoreData } from '../store'
	import { SiteInfo } from '../dto'
	const { sitemap } = getEditDomainStoreData()
	const route = useRoute()
	const domain = route.params.domain as string
	getSitemapInfo(domain)

	/**
	 * @description Add site url
	 */
	async function handleSave(siteInfo: SiteInfo, index: number) {
		await addSitemapInfo(domain, siteInfo.title, siteInfo.uri_path)
		sitemap.value[index].isSaved = true
	}

	/**
	 * @description remove site url
	 */
	async function handleRemove(siteInfo: SiteInfo, index: number) {
		if (siteInfo.title && siteInfo.uri_path) {
			await removeSiteMapInfo(domain, siteInfo.uri_path)
		}
		sitemap.value.splice(index, 1)
	}

	/**
	 * @description Add link form
	 */
	function handleAdd() {
		sitemap.value.push({
			title: '',
			uri_path: '',
		})
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

		.inline-form-items {
			@include base.row-flex;
			width: 100%;
			justify-content: space-between;
			gap: 10px;

			.name {
				flex: 3.5;
			}

			.url {
				flex: 3.5;
			}

			.type {
				flex: 2;
			}

			.operation {

				@include mixin.operation-close();

				&.save {
					color: var(--color-primary-1);
					border-color: var(--color-primary-1);
				}

				&.save:hover {
					color: #fff;
					background: var(--color-primary-hover-1);
				}

				&.disabled {
					opacity: 0.5;
					cursor: not-allowed;
				}
			}
		}
	}
</style>
