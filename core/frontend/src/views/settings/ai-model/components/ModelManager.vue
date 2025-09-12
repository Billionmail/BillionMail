<template>
	<!-- <n-modal preset="card" draggable :close-on-esc="false" :mask-closable="false" title="Model manager"
        class="w-180 customer-modal" segmented v-model:show="show"> -->
	<div class="manager-wrapper">
		<!-- Provider list -->
		<div class="left-provider">
			<div class="provider-list">
				<div v-for="item in providerList" :key="item.supplierName"
					:class="['provider-item', { active: item.supplierName == currentProvider?.supplierName }]"
					@click="getModelListBySupplier(item)">
					<div class="item-icon">
						<n-image v-if="item.icon" :src="item.icon" height="24" width="24"></n-image>
						<i v-else class="i-ai:big-model w-6.5 h-6.5"></i>
					</div>
					<span class="tit">{{ item.supplierTitle[0].toUpperCase() + item.supplierTitle.slice(1) }}</span>
					<span :class="['status', { active: item.status }]"></span>
				</div>
			</div>
			<div class="add-privider">
				<n-button @click="handleAddProvider">
					<template #icon>
						<i class="i-ic:baseline-add-circle"></i>
					</template>
					Add model service provider
				</n-button>
			</div>
		</div>

		<!-- Configuration -->
		<n-spin :show="configurationLoading">
			<div class="right-configuration">
				<div class="top-switch">
					<div class="switch-info">
						<!-- <i class="i-ic:baseline-error text-5"></i> -->
						<span class="tit">{{ currentProvider.supplierName ? currentProvider.supplierName[0].toUpperCase()
							+
							currentProvider.supplierName.slice(1):"" }}</span>
						<n-switch v-model:value="currentProvider.status"
							@update:value="status => changeProviderStatus(status, modelStore)"></n-switch>
					</div>
					<i class="i-ri:delete-bin-3-line text-5.5 hover:text-red-5 cursor-pointer"
						@click="removeProvider(modelStore)"></i>
				</div>
				<div class="center-api">
					<n-form class="mt-15px">
						<n-form-item :label="$t('settings.aiModel.aPIKey')">
							<div class="w-100%">
								<n-input-group>
									<n-input v-model:value="currentProvider.apiKey"></n-input>
									<n-button @click="checkProviderApiConfiguration(modelStore)">{{$t("settings.aiModel.check")}}</n-button>
								</n-input-group>
								<n-button text type="info" class="mt-5px"
									@click="getProviderConfiguration(modelStore)">{{$t("settings.aiModel.getKey")}}</n-button>
							</div>
						</n-form-item>
						<n-form-item :label="$t('settings.aiModel.apiPath')">
							<div class="w-100%">
								<n-input v-model:value="currentProvider.baseUrl"></n-input>
								<span class="text-[var(--color-text-3)] mt-5">{{$t("settings.aiModel.example")}}: https://api.deepseek.com/v1</span>
							</div>
						</n-form-item>
					</n-form>
					<n-button type="primary" @click="setProviderConfiguration(modelStore)">{{$t("settings.aiModel.saveAPI")}}</n-button>
				</div>
				<div class="bottom-model-list">
					<div class="header-tit">
						<div>
							<span class="tit">{{$t("settings.aiModel.model")}}</span>
							<span class="sub-tit">{{$t("settings.aiModel.byDefault")}}</span>
						</div>
						<div class="add-model" @click="handleAddModel">
							<i class="i-ic:baseline-control-point text-4"></i>
							<span class="tit">{{$t("settings.aiModel.addModel")}}</span>
						</div>
					</div>
					<div v-for="item in modelList" :key="item.title" class="model-list">
						<div class="model-item">
							<!-- <i class="i-ic:round-check-circle-outline text-5"></i> -->
							<span class="model-name">{{ item.title }}</span>
							<div class="operation">
								<n-switch v-model:value="item.status" @update:value="
									status => setModelStatus(item, status, modelStore)
								"></n-switch>
								<i class="i-material-symbols:delete-outline text-5" @click="removeModel(item,modelStore)"></i>
							</div>
						</div>
					</div>
				</div>
			</div>
		</n-spin>
	</div>

	<!-- Add Provider -->
	<AddProvider ref="addProviderRef" />

	<!-- Add Model -->
	<AddModel ref="addModelRef" />
</template>

<script setup lang="ts">
import AddProvider from './AddProvider.vue'
import AddModel from './AddModel.vue'
import { ModelStore, Provider } from '../dto'
import {
	getModelList,
	getProviderList,
	getProviderConfiguration,
	changeProviderStatus,
	checkProviderApiConfiguration,
	setProviderConfiguration,
	setModelStatus,
	removeProvider,
	removeModel
} from '../controller'
const modelStore = inject<ModelStore>('modelStore')!
const {
	providerList,
	modelList,
	currentProvider,
	configurationLoading,
	addProviderRef,
	addModelRef,
} = modelStore
getProviderList(modelStore)

/**
 * @description Get model list
 */
function getModelListBySupplier(provider: Provider) {
	currentProvider.value = provider
	getModelList(provider.supplierName, modelStore)
}

/**
 * @description Handle add provider
 */
function handleAddProvider() {
	addProviderRef.value.open()
}

/**
 * @description Handle add  model
 */
function handleAddModel() {
	addModelRef.value.open()
}
</script>

<style scoped lang="scss">
@use '@/styles/index.scss' as base;

.manager-wrapper {
	// height: 480px;
	display: grid;
	grid-template-columns: 230px 1fr;
	/* border-top: 1px solid var(--color-border-2);
        border-bottom: 1px solid var(--color-border-2); */

	.left-provider {
		height: 100%;
		display: grid;
		grid-template-rows: 1fr 60px;
		border-right: 1px solid var(--color-border-2);

		.provider-list {
			@include base.col-flex;
			gap: 0;

			.provider-item {
				height: 50px;
				width: 100%;
				box-sizing: border-box;
				padding-left: 10px;
				border-bottom: 1px solid var(--color-border-1);
				@include base.row-flex-start;
				gap: 5px;
				align-items: center;
				transition: 0.15s all ease-in-out;
				cursor: pointer;

				.tit {
					font-size: 14px;
					font-weight: bold;
				}

				&:hover {
					background: var(--color-primary-2);
				}

				&.active {
					background: var(--color-primary-2);
				}

				.item-icon {
					width: 32px;
					@include base.row-flex-center;
				}

				.status {
					display: block;
					width: 8px;
					height: 8px;
					background: var(--color-text-3);
					border-radius: 50%;

					&.active {
						background: var(--color-primary-1)
					}
				}
			}
		}

		.add-privider {
			@include base.row-flex-center;
		}
	}

	.right-configuration {
		padding: 0 15px 15px;

		.top-switch {
			height: 50px;
			@include base.row-flex;
			align-items: center;
			justify-content: space-between;
			border-bottom: 1px solid var(--color-border-2);

			.switch-info {
				@include base.row-flex-start;
				align-items: center;
				gap: 5px;

				.tit {
					font-size: 14px;
					font-weight: bold;
				}
			}
		}

		.center-api {
			padding-bottom: 15px;
			border-bottom: 1px solid var(--color-border-2);
		}

		.bottom-model-list {
			margin-top: 15px;

			.header-tit {
				@include base.row-flex;
				justify-content: space-between;
				margin-bottom: 15px;

				.tit {
					font-weight: bold;
					font-size: 14px;
					margin-right: 5px;
				}

				.sub-tit {
					color: var(--color-text-3);
				}

				.add-model {
					@include base.row-flex-start;
					gap: 5px;
					align-items: center;
					cursor: pointer;

					.tit {
						font-size: 14px;
					}
				}
			}

			.model-list {
				@include base.col-flex;
				justify-content: flex-start;

				.model-item {
					@include base.row-flex;
					justify-content: space-between;
					width: 100%;
					align-items: center;
					padding: 10px 5px;
					transition: 0.15s all ease-in-out;
					cursor: pointer;

					i.active {
						color: var(--color-primary-1);
					}

					.model-name {
						font-weight: bold;
						font-size: 14px;
					}

					&:hover {
						background: #eef9ee;
					}

					.operation {
						@include base.row-flex-start;
						gap: 10px;
					}
				}
			}
		}
	}
}
</style>

<style>
.customer-modal {
	.n-card__content {
		padding: 0 !important;
	}
}
</style>
