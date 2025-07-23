<template>
	<modal :title="title" :width="600">
		<div class="pt-16px">
			<bt-form ref="formRef" :model="form" :rules="rules">
				<n-form-item path="domain">
					<template #label>
						<div class="flex items-center justify-start gap-1.25">
							<span>{{ t('domain.form.domain') }}</span>
							<n-popover trigger="hover">
								<template #trigger>
									<i class="i-custom:help text-primary cursor-pointer"></i>
								</template>
								<bt-tips>
									<li class="text-error">{{ t('domain.form.tips.aRecordFailed') }}</li>
									<li>{{ t('domain.form.tips.dnsSetup') }}</li>
									<li>{{ t('domain.form.tips.cloudflare') }}</li>
								</bt-tips>
							</n-popover>
						</div>
					</template>
					<n-input v-model:value="form.domain" :disabled="isEdit"
						:placeholder="t('domain.form.domainPlaceholder')" @update:value="syncToUrls">
					</n-input>
				</n-form-item>
				<n-form-item v-if="false" label="A记录">
					<n-input v-model:value="form.a_record" :disabled="isEdit" placeholder="请输入A记录，例如：mail.aapanel.com">
					</n-input>
				</n-form-item>
				<n-form-item :label="t('domain.form.quota')">
					<n-input-number v-model:value="form.quota" class="flex-1" :min="0" :show-button="false">
					</n-input-number>
					<div class="w-100px ml-20px">
						<n-select v-model:value="form.quota_unit" :options="unitOptions"></n-select>
					</div>
				</n-form-item>
				<n-form-item :label="t('domain.form.mailboxCount')">
					<n-input-number v-model:value="form.mailboxes" class="flex-1" :min="0" :show-button="false">
					</n-input-number>
				</n-form-item>
				<n-form-item :label="t('domain.form.globalCatch')">
					<n-input v-model:value="form.email" :placeholder="t('domain.form.globalCatchPlaceholder')">
					</n-input>
				</n-form-item>

				<n-form-item>
					<template #label>
						<div class="flex justify-start items-center ">
							<i class="i-domain:brand-info w-5 h-5 mr-1.25 "></i>
							<span>{{ $t("domain.form.createBrandInfo") }}</span>
						</div>
					</template>
					<n-switch v-model:value="initAi" :disabled="!aiConfigurationStatus"></n-switch>
				</n-form-item>
				<n-alert v-if="!aiConfigurationStatus" style="margin: 0 0 15px 0" type="warning" :show-icon="false">
					<div class="w-100% flex justify-between items-center">
						<span class="mr-5">{{ $t("domain.form.modelNotice") }}</span>
						<n-button type="primary" @click="goIntegrate">{{ $t("domain.form.integrateImmediately") }}</n-button>
					</div>
				</n-alert>
				<div class="text-[#777] flex justify-start">
					<span><i class="i-domain:brand-info w-5 h-5 mr-1.25"></i></span>
					<span>{{ $t("domain.form.modelDescription") }}</span>
				</div>
				<bt-tips style="margin-bottom: 15px">
					<li>{{ $t("domain.form.extractBrand") }}</li>
					<li>{{ $t("domain.form.analyzeStructure") }}</li>
					<li>{{ $t("domain.form.importContent") }}</li>
					<li>{{ $t("domain.form.customLogo") }}</li>
				</bt-tips>
				<n-form-item :label="$t('domain.form.specifyDomain')">
					<div class="w-100% flex flex-col gap-2.5">
						<!-- <n-input v-for="(item, index) in urls" :key="index" v-model:value="urls[index]" placeholder="">
						</n-input> -->
						<div v-for="(_, index) in urls" :key="index" class="flex justify-start items-center gap-2.5">
							<n-input v-model:value="urls[index]"
								:placeholder="t('domain.form.urlsPlacement')"  :disabled="!aiConfigurationStatus"></n-input>
							<div v-if="index != 0" class="close" @click="removeUrl(index)">
								<i class="i-material-symbols:close-rounded text-5"></i>
							</div>
							<!-- <div v-else class="w-34px h-34px"></div> -->
						</div>
						<!-- <div class="text-[#777]">{{ $t("domain.form.maxUrl") }}</div> -->

						<!-- <n-button type="primary" :disabled="!aiConfigurationStatus || urls.length == 3" ghost @click="addUrl">
							<template #icon>
								<i class="i-material-symbols:add-circle-outline"></i>
							</template>
							{{ $t("domain.form.addMoreUrls") }}
						</n-button> -->
					</div>
				</n-form-item>
			</bt-form>
		</div>
	</modal>

	<!-- Wait for init brand info -->
	<WaitAndCheckDomainStatus ref="waitAndCheckDomainStatusRef" />


</template>

<script lang="ts" setup>
import WaitAndCheckDomainStatus from './WaitAndCheckDomainStatus.vue'
import { FormRules } from 'naive-ui'
import { getByteUnit, getNumber } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import {
	createDomain,
	initAiConfiguration,
	updateDomain,
	checkAiConfiguration,
} from '@/api/modules/domain'
import type { MailDomain } from '../interface'
import router from '@/router'
import { useGlobalStore } from '@/store'

const { t } = useI18n()

const isEdit = ref(false)
const waitAndCheckDomainStatusRef = ref()

const title = computed(() => {
	return isEdit.value ? t('domain.form.editTitle') : t('domain.form.addTitle')
})

const aiConfigurationStatus = ref(false)
const globalStore = useGlobalStore()
const formRef = useTemplateRef('formRef')
const initAi = ref(false)
const urls = ref(['https://'])
const form = reactive({
	domain: '',
	a_record: '',
	quota: 5,
	quota_unit: 'GB',
	mailboxes: 50,
	email: '',
})

const unitOptions = [
	{ label: 'GB', value: 'GB' },
	{ label: 'MB', value: 'MB' },
]

const rules: FormRules = {
	domain: {
		trigger: ['blur', 'input'],
		validator: () => {
			if (form.domain.trim() === '') {
				return new Error(t('domain.form.validation.domainRequired'))
			}
			return true
		},
	},
}

/**
 * @description Calculate the byte number based on the domain quota and unit
 * @param quota
 * @param quota_unit
 */
const getQuotaByte = (quota: number, quota_unit: string) => {
	switch (quota_unit) {
		case 'GB':
			return quota * 1024 * 1024 * 1024
		case 'MB':
			return quota * 1024 * 1024
		default:
			return quota
	}
}

/**
 * @description Sync domain to urls
 */
const syncToUrls = (domainVal: string) => {
	const httpStr = urls.value[0].match(/http:\/\/?/g)
	const httpsStr = urls.value[0].match(/https:\/\/?/g)
	if (httpStr) {
		urls.value[0] = httpStr[0] + domainVal
	}

	if (httpsStr) {
		urls.value[0] = httpsStr[0] + domainVal
	}

	if (!httpStr && !httpsStr) {
		urls.value[0] = 'https://' + domainVal
	}
}

/**
 * @description Remove url
 */
const removeUrl = (index: number) => {
	urls.value.splice(index, 1)
}

const [Modal, modalApi] = useModal({
	onChangeState: async isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ isEdit: boolean; row: MailDomain | null }>()
			isEdit.value = state.isEdit
			const res = (await checkAiConfiguration()) as Record<string, any>
			aiConfigurationStatus.value = res.is_configured
			if (state.row) {
				const { row } = state
				form.domain = row.domain
				form.a_record = row.a_record
				const quota = getByteUnit(row.quota)
				form.quota = getNumber(quota.split(' ')[0])
				form.quota_unit = quota.split(' ')[1]
				form.mailboxes = row.mailboxes
				form.email = row.email
			}
		} else {
			form.domain = ''
			form.a_record = ''
			form.quota = 5
			form.quota_unit = 'GB'
			form.mailboxes = 50
			form.email = ''
			urls.value = ['https://']
		}
	},
	onConfirm: async () => {
		await formRef.value?.validate()
		if (isEdit.value) {
			await updateDomain({
				domain: form.domain,
				quota: getQuotaByte(form.quota, form.quota_unit),
				mailboxes: form.mailboxes,
				email: form.email,
				urls: urls.value,
			})
		} else {
			await createDomain({
				domain: form.domain,
				quota: getQuotaByte(form.quota, form.quota_unit),
				mailboxes: form.mailboxes,
				email: form.email,
				urls: urls.value,
				hasbrandinfo:Number(initAi.value),
			})
			
			// Init Ai configuration (via. src\api\modules\domain.ts)
			if (initAi.value) {
				await initAiConfiguration({
					domain: form.domain,
					urls: urls.value,
				})
				waitAndCheckDomainStatusRef.value.open(form.domain)
				globalStore.domainSource = form.domain
			}else{
				globalStore.domainSource = ""
			}

		}
		const state = modalApi.getState<{ refresh: Function }>()
		state.refresh()
	},
})



/**
 * @description Go to integrate AI model
 */
function goIntegrate() {
	router.push({
		name: "AiModel"
	})
}
</script>

<style lang="scss" scoped>
@use '@/views/domain/pages/editDomain/components/mixin.scss';

.close {
	@include mixin.operation-close;
}
</style>
