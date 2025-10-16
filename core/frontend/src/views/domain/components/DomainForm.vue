<template>
	<modal :title="title" :width="600">
		<div class="max-h-640px pt-16px overflow-auto">
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
					<n-input
						v-model:value="form.domain"
						:disabled="isEdit"
						:placeholder="t('domain.form.domainPlaceholder')"
						@update:value="syncToUrls">
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
					<n-input-number
						v-model:value="form.mailboxes"
						class="flex-1"
						:min="0"
						:show-button="false">
					</n-input-number>
				</n-form-item>
				<n-form-item :label="$t('domain.form.dedicatedIp')">
					<div class="flex-1 mr-16px">
						<n-input v-model:value="form.outbound_ip" :placeholder="$t('domain.form.notSet')">
						</n-input>
					</div>
					<n-button type="primary" ghost @click="onTestConnection">
						{{ $t('domain.form.testConnection') }}
					</n-button>
				</n-form-item>
				<n-form-item label="Hostname" path="hostname">
					<n-input v-model:value="form.hostname" :placeholder="$t('domain.form.notSet')"> </n-input>
				</n-form-item>
				<n-form-item :label="t('domain.form.globalCatch')">
					<n-input
						v-model:value="form.email"
						:placeholder="t('domain.form.globalCatchPlaceholder')">
					</n-input>
				</n-form-item>
				<bt-more>
					<template #title>
						<div class="flex items-center">
							<i class="i-domain:brand-info w-20px h-20px mr-6px"></i>
							<span>{{ $t('domain.form.createBrandInfo') }}</span>
						</div>
					</template>
					<n-form-item :show-label="false">
						<n-switch v-model:value="initAi" :disabled="!aiConfigurationStatus"></n-switch>
					</n-form-item>
					<n-alert
						v-if="!aiConfigurationStatus"
						class="mb-16px"
						size="small"
						type="warning"
						:show-icon="false">
						<div class="w-100% flex justify-between items-center">
							<span class="mr-5">{{ $t('domain.form.modelNotice') }}</span>
							<n-button type="primary" size="small" @click="goIntegrate">
								{{ $t('domain.form.integrateImmediately') }}
							</n-button>
						</div>
					</n-alert>
					<div class="mb-8px text-default flex justify-start">
						<span><i class="i-domain:brand-info w-5 h-5 mr-4px"></i></span>
						<span>{{ $t('domain.form.modelDescription') }}</span>
					</div>
					<bt-tips style="margin-bottom: 15px">
						<li>{{ $t('domain.form.extractBrand') }}</li>
						<li>{{ $t('domain.form.analyzeStructure') }}</li>
						<li>{{ $t('domain.form.importContent') }}</li>
						<li>{{ $t('domain.form.customLogo') }}</li>
					</bt-tips>
					<n-form-item :label="$t('domain.form.specifyDomain')">
						<div class="w-100% flex flex-col gap-2.5">
							<!-- <n-input v-for="(item, index) in urls" :key="index" v-model:value="urls[index]" placeholder="">
						</n-input> -->
							<div
								v-for="(_, index) in urls"
								:key="index"
								class="flex justify-start items-center gap-2.5">
								<n-input
									v-model:value="urls[index]"
									:placeholder="t('domain.form.urlsPlacement')"
									:disabled="!aiConfigurationStatus"></n-input>
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
				</bt-more>
			</bt-form>
		</div>
	</modal>

	<!-- Wait for init brand info -->
	<WaitAndCheckDomainStatus ref="waitAndCheckDomainStatusRef" />
</template>

<script lang="ts" setup>
import WaitAndCheckDomainStatus from './WaitAndCheckDomainStatus.vue'
import { FormRules } from 'naive-ui'
import { useGlobalStore } from '@/store'
import { getByteUnit, getNumber, Message } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import {
	createDomain,
	initAiConfiguration,
	updateDomain,
	checkAiConfiguration,
	testConnection,
} from '@/api/modules/domain'
import type { MailDomain } from '../interface'
import router from '@/router'

const { t } = useI18n()

const isEdit = ref(false)
const waitAndCheckDomainStatusRef = ref()

const title = computed(() => {
	return isEdit.value ? t('domain.form.editTitle') : t('domain.form.addTitle')
})

const globalStore = useGlobalStore()

const aiConfigurationStatus = ref(false)

const formRef = useTemplateRef('formRef')

const initAi = ref(false)

const urls = ref(['https://'])

const form = reactive({
	domain: '',
	hostname: '',
	a_record: '',
	quota: 5,
	quota_unit: 'GB',
	mailboxes: 50,
	outbound_ip: '',
	email: '',
})

const unitOptions = [
	{ label: 'GB', value: 'GB' },
	{ label: 'MB', value: 'MB' },
]

const rules: FormRules = {
	domain: {
		required: true,
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

/**
 * @description Test connection
 */
const onTestConnection = async () => {
	if (form.domain == '') {
		Message.error(t('domain.form.validation.domainInputRequired'))
		return
	}
	if (form.outbound_ip == '') {
		Message.error(t('domain.form.validation.dedicatedIpRequired'))
		return
	}
	await testConnection({
		domain: form.domain,
		outbound_ip: form.outbound_ip,
	})
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
				form.hostname = row.a_record
				const quota = getByteUnit(row.quota)
				form.quota = getNumber(quota.split(' ')[0])
				form.quota_unit = quota.split(' ')[1]
				form.mailboxes = row.mailboxes
				form.email = row.email
			}
		} else {
			form.domain = ''
			form.a_record = ''
			form.hostname = ''
			form.quota = 5
			form.quota_unit = 'GB'
			form.mailboxes = 50
			form.email = ''
			form.outbound_ip = ''
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
				outbound_ip: form.outbound_ip,
				hostname: form.hostname,
			})
		} else {
			await createDomain({
				domain: form.domain,
				quota: getQuotaByte(form.quota, form.quota_unit),
				mailboxes: form.mailboxes,
				email: form.email,
				urls: urls.value,
				hasbrandinfo: Number(initAi.value),
				outbound_ip: form.outbound_ip,
				hostname: form.hostname,
			})

			// Init Ai configuration (via. src\api\modules\domain.ts)
			if (initAi.value) {
				await initAiConfiguration({
					domain: form.domain,
					urls: urls.value,
				})
				waitAndCheckDomainStatusRef.value.open(form.domain)
				globalStore.domainSource = form.domain
			} else {
				globalStore.domainSource = ''
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
		name: 'AiModel',
	})
}
</script>

<style lang="scss" scoped>
@use '@/views/domain/pages/editDomain/components/mixin.scss';

.close {
	@include mixin.operation-close;
}
</style>
