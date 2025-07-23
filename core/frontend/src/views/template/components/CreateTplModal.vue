<template>
	<n-modal v-model:show="show" preset="card" draggable :close-on-esc="false" :mask-closable="false" segmented
		class="w-110" title="">
		<div class="wrapper">
			<div class="creation-methods">
				<div v-for="(item, index) in computedMethodsList" :key="index"
					:class="['choose-item', { active: choosedMethod == item }]" @click="choosedMethod = item">
					<span class="item-label">{{ item }}</span>
				</div>
			</div>
			<div :class="['url-source', { hidden: choosedMethod !== 'AI' }]">
				<span class="label">{{ $t("template.createTpl.sourceUrl") }}</span>
				<n-select v-model:value="sourceDomain" class="flex-1" label-field="domain" value-field="domain"
					:options="domainListHasBrandInfo" :disabled="canNotUse">
				</n-select>
			</div>
			<div class="desc">
				{{ $t("template.createTpl.useAiTools") }}
			</div>
		</div>

		<template #footer>
			<div class="flex justify-end">
				<n-button type="primary" :disabled="canNotUse" @click="createTemplate">{{
					$t("template.createTpl.create") }}</n-button>
			</div>
		</template>
	</n-modal>
</template>

<script setup lang="ts">
import { instance } from '@/api'
import { createAiTemplate } from '../pages/AITemplate/controller'
import { useGlobalStore } from '@/store'
// import { TemplateStore } from '../pages/AITemplate/dto'

// const store = inject<TemplateStore>('modelStore')!
const props = defineProps<{
	onlyAi?: boolean,
}>()
const globalStore = useGlobalStore()
const router = useRouter()
const methodsList = ref(['Drag', 'AI', 'HTML'])
const choosedMethod = ref('AI')
const sourceDomain = ref('')
const show = ref(false)
const emits = defineEmits(['confirmType', 'hasCreateTpl'])
const domainList = ref<any>([])

const computedMethodsList = computed(() => {
	if (props.onlyAi) {
		return ["AI"]
	} else {
		return methodsList.value
	}
})

const domainListHasBrandInfo = computed(() => {
	return domainList.value.filter((item: any) => item.hasbrandinfo == 1)
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
function open() {
	getDomainList()
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
		const chatId = await createAiTemplate(sourceDomain.value)
		if (chatId) {
			globalStore.domainSource = sourceDomain.value
			router.push({ name: 'ai-template', params: { chatId } })
		}
	} else {
		emits('confirmType', choosedMethod.value)
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
