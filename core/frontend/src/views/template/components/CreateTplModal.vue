<template>
	<n-modal
		v-model:show="show"
		preset="card"
		draggable
		:close-on-esc="false"
		:mask-closable="false"
		segmented
		class="w-110"
		title="">
		<div class="wrapper">
			<div class="creation-methods">
				<div
					v-for="(item, index) in computedMethodsList"
					:key="index"
					:class="['choose-item', { active: choosedMethod == item }]"
					@click="choosedMethod = item">
					<span class="item-label">{{ item }}</span>
				</div>
			</div>
			<div :class="['url-source', { hidden: choosedMethod !== 'AI' }]">
				<span class="label">{{ $t('template.createTpl.sourceUrl') }}</span>
				<n-select
					v-model:value="sourceDomain"
					class="flex-1"
					label-field="domain"
					value-field="domain"
					:options="domainListHasBrandInfo"
					:disabled="canNotUse"
					:render-label="renderLabel">
				</n-select>
			</div>
			<div v-if="noticeShowFlag == 'normal'" class="desc">
				{{ $t('template.createTpl.useAiTools') }}
			</div>
			<div v-else-if="noticeShowFlag == 'domain-list-empty'">
				{{ $t('template.createTpl.notices.domainListEmpty') }},
				<n-button text type="primary" @click="jumpToDomainCreate">{{
					$t('template.createTpl.buttons.createNow')
				}}</n-button>
			</div>
			<div v-else-if="noticeShowFlag == 'ai-configuration-invalid'">
				{{ $t('template.createTpl.notices.aiConfigurationInvalid') }},
				<n-popover trigger="hover" placement="right">
					<template #trigger>
						<n-button text type="primary" @click="jumpToAiSettings">{{
							$t('template.createTpl.buttons.configureNow')
						}}</n-button>
					</template>
					<n-image :src="aiModelNotice" width="600"></n-image>
				</n-popover>
			</div>
			<div v-else-if="noticeShowFlag == 'invalid-brand-domain'">
				{{ $t('template.createTpl.notices.invalidBrandDomain') }},
				<n-popover trigger="hover" placement="right">
					<template #trigger>
						<n-button text type="primary" @click="jumpToDomainEdit">{{
							$t('template.createTpl.buttons.createNow')
						}}</n-button>
					</template>
					<n-image :src="brandInfoNotice" width="600"></n-image>
				</n-popover>
			</div>
		</div>

		<template #footer>
			<div class="flex justify-end">
				<n-button
					v-if="choosedMethod == 'AI'"
					type="primary"
					:disabled="
						canNotUse || ['domain-list-empty', 'ai-configuration-invalid'].includes(noticeShowFlag)
					"
					@click="createTemplate"
					>{{ $t('template.createTpl.create') }}</n-button
				>
				<n-button v-else type="primary" @click="createTemplate">{{
					$t('template.createTpl.create')
				}}</n-button>
			</div>
		</template>
	</n-modal>
</template>

<script setup lang="tsx">
import { instance } from '@/api'
import { createAiTemplate } from '../pages/AITemplate/controller'
import { useGlobalStore } from '@/store'
import { checkAiConfiguration, initAiConfiguration } from '@/api/modules/domain'
import aiModelNotice from '@/assets/images/template/model-notice.png'
import brandInfoNotice from '@/assets/images/template/create-brand-info.png'
import { SelectOption } from 'naive-ui'
import { Message } from '@/utils'
import { updateHasBrandInfo } from '@/views/domain/pages/editDomain/controller/domainConfiguration.controller'
// import { TemplateStore } from '../pages/AITemplate/dto'

// const store = inject<TemplateStore>('modelStore')!
const props = defineProps<{
	onlyAi?: boolean
}>()
const globalStore = useGlobalStore()
const router = useRouter()
const methodsList = ref(['Drag', 'AI', 'HTML'])
const choosedMethod = ref('AI')
const sourceDomain = ref('')
const currentDomainOption = ref<SelectOption | null>(null)
const show = ref(false)
const emits = defineEmits(['confirmType', 'hasCreateTpl'])
const domainList = ref<any>([])
const aiConfigurationStatus = ref(false)

const computedMethodsList = computed(() => {
	if (props.onlyAi) {
		return ['AI']
	} else {
		return methodsList.value
	}
})

/**
 * @description Calculate the display of prompt information based on AI configuration, domain name list and other information
 */
const noticeShowFlag = computed(() => {
	if (domainListHasBrandInfo.value.length == 0) {
		return 'domain-list-empty'
	}

	if (!aiConfigurationStatus.value) {
		return 'ai-configuration-invalid'
	}

	const domainInfo = domainList.value.find((item: any) => item.domain == sourceDomain.value)
	if (domainInfo && domainInfo.hasbrandinfo !== 1) {
		return 'invalid-brand-domain'
	}

	return 'normal'
})

/**
 * @description Calculate the list of domain names for dropdown options
 */
const domainListHasBrandInfo = computed(() => {
	return [...domainList.value].sort((a, b) => b.hasbrandinfo - a.hasbrandinfo)
})

/**
 * @description Whether the button can be used
 */
const canNotUse = computed(() => {
	if (choosedMethod.value == 'AI' && domainListHasBrandInfo.value.length == 0) {
		return true
	}
	return false
})

/**
 * @description open modal
 */
async function open() {
	const res = (await checkAiConfiguration()) as Record<string, any>
	aiConfigurationStatus.value = res.is_configured
	await getDomainList()

	if (globalStore.domainSource) {
		globalStore.domainSource = sourceDomain.value
	}
	show.value = true
}

/**
 * @description close modal
 */
function close() {
	show.value = false
}

/**
 * @description jump
 */
async function createTemplate() {
	if (choosedMethod.value == 'AI') {
		if (noticeShowFlag.value == 'invalid-brand-domain') {
			const currentDomain = domainList.value.find((item: any) => item.domain === sourceDomain.value)
			try {
				await initAiConfiguration({
					domain: sourceDomain.value,
					urls: currentDomain.urls,
				})
				updateHasBrandInfo(sourceDomain.value, 1)
			} catch (error) {
				Message.error('Failed to initialize AI configuration, please try again later.')
				console.warn(error)
			}
		}
		const chatId = await createAiTemplate(sourceDomain.value)
		if (chatId) {
			globalStore.domainSource = sourceDomain.value
			router.push({ name: 'ai-template', params: { chatId } })
		}
	} else {
		emits('confirmType', choosedMethod.value)
	}
}

/**
 * @description Jump to domain and open domain create modal
 */
function jumpToDomainCreate() {
	router.push({
		name: 'Domain',
		query: {
			init: 'init-domain',
		},
	})
}

/**
 * @description Jump to ai settings
 */
function jumpToAiSettings() {
	router.push({
		name: 'AiModel',
	})
}

/**
 * @description Jump to domain edit
 */
function jumpToDomainEdit() {
	router.push({
		name: 'EditDomain',
		params: {
			domain: sourceDomain.value,
		},
	})
}

/**
 * @description Render select label
 */
function renderLabel(option: SelectOption) {
	if (option.hasbrandinfo) {
		return (
			<div>
				<i class="i-domain:brand-info w-4 h-4 mr-1.25"></i> <span>{option.domain}</span>
			</div>
		)
	} else {
		return <span>{option.domain}</span>
	}
}

defineExpose({
	open,
	close,
})

/**
 * @description Get domain list
 */
async function getDomainList() {
	const res = (await instance.get('/domains/list', {
		params: {
			page: 1,
			page_size: 100,
		},
	})) as Record<string, any>
	domainList.value = res.list
	currentDomainOption.value =
		domainList.value.find((item: SelectOption) => item.domain === sourceDomain.value) || null
	if (domainList.value.length == 0) {
		globalStore.domainSource = ''
		sourceDomain.value = ''
		return
	}
	if (globalStore.domainSource) {
		sourceDomain.value = globalStore.domainSource
	}
	if (domainListHasBrandInfo.value.length > 0) {
		sourceDomain.value = domainListHasBrandInfo.value[0].domain
		globalStore.domainSource = domainListHasBrandInfo.value[0].domain
	}
}
</script>

<style scoped lang="scss">
@use '@/styles/index' as base;

.wrapper {
	@include base.col-flex-center;
	height: 153px;
	gap: 20px;

	.creation-methods {
		@include base.row-flex-center;
		border-bottom: 1px solid var(--color-border-1);
		width: 90%;
		gap: 25px;

		.choose-item {
			@include base.row-flex-start;
			gap: 5px;
			padding: 6px 15px;
			align-items: center;
			cursor: pointer;
			color: var(--color-text-2);
			transition: 0.1s all ease-in-out;
			box-sizing: border-box;

			.item-label {
				font-size: 16px;
				transition: 0.2s all ease-in-out;
			}

			&:hover {
				color: var(--color-primary-1);
				// transform: scale(1.3) translate(0, -5px);
			}

			&.active {
				color: var(--color-primary-1);
				transform: scale(1.3) translate(0, -5px);
				font-weight: bold;
				border-bottom: 2px solid var(--color-primary-1);
			}
		}
	}

	.url-source {
		width: 90%;
		@include base.row-flex-start;
		gap: 10px;

		&.hidden {
			visibility: hidden;
		}
	}

	.desc {
		width: 90%;
		font-size: 14px;
		color: var(--color-text-3);
	}
}
</style>
