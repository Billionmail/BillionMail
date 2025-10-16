<template>
	<div class="p-24px">
		<div class="bt-title">{{ $t('smtp.title') }}</div>
		<div class="flex gap-12px mb-16px">
			<n-dropdown
				placement="bottom-start"
				trigger="hover"
				size="large"
				:options="addDropdownOptions"
				@select="handleSelectAdd">
				<n-button type="primary">
					<span class="mr-4px">{{ $t('common.actions.add') }}</span>
					<i class="i-mdi-chevron-down text-17px"></i>
				</n-button>
			</n-dropdown>
			<bt-help href="https://www.billionmail.com/start/smtp.html" :text="$t('smtp.description')">
			</bt-help>
		</div>
		<smtp-loading v-if="loading"></smtp-loading>
		<div
			v-else-if="smtpServices.length > 0"
			class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-16px">
			<SmtpCard
				v-for="service in smtpServices"
				:key="service.id"
				:service="service"
				@edit="handleEdit"
				@delete="handleDelete"
				@show-dns="handleShowDns">
			</SmtpCard>
		</div>
		<div v-else class="flex-center h-400px text-center text-desc">
			<bt-table-help></bt-table-help>
		</div>

		<form-modal></form-modal>
		<smtp-dns-modal></smtp-dns-modal>
	</div>
</template>

<script lang="ts" setup>
import { DropdownOption } from 'naive-ui'
import { confirm, isArray, isObject } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { deleteSmtp, getSmtpList } from '@/api/modules/smtp'
import type { SmtpService } from './types/base'

import SmtpCard from './components/SmtpCard.vue'
import SmtpForm from './components/SmtpForm.vue'
import SmtpDns from './components/SmtpDns.vue'
import SmtpLoading from './components/SmtpLoading.vue'

const { t } = useI18n()

const loading = ref(false)

const smtpServices = ref<SmtpService[]>([])

const addDropdownOptions: DropdownOption[] = [
	{
		label: 'Gmail',
		key: 'gmail',
	},
	{
		label: 'Mailgun',
		key: 'mailgun',
	},
	{
		label: 'AWS SES',
		key: 'aws',
	},
	{
		label: 'SendGrid',
		key: 'sendgrid',
	},
	{
		label: t('smtp.providers.custom'),
		key: 'custom',
	},
]

const handleSelectAdd = (key: string) => {
	formModalApi.setState({
		isEdit: false,
		type: key,
		row: null,
	})
	formModalApi.open()
}

const getCardList = async () => {
	try {
		loading.value = true
		const res = await getSmtpList()
		if (isObject<{ list: SmtpService[] }>(res)) {
			smtpServices.value = isArray<SmtpService>(res.list) ? res.list : []
		}
	} finally {
		loading.value = false
	}
}

const [FormModal, formModalApi] = useModal({
	component: SmtpForm,
	state: {
		isEdit: false,
		type: 'custom',
		refresh: getCardList,
	},
})

const handleEdit = (service: SmtpService) => {
	formModalApi.setState({
		isEdit: true,
		row: service,
	})
	formModalApi.open()
}

const [SmtpDnsModal, smtpDnsModalApi] = useModal({
	component: SmtpDns,
	state: {
		isEdit: false,
		type: 'custom',
		refresh: getCardList,
	},
})

const handleShowDns = (service: SmtpService) => {
	smtpDnsModalApi.setState({
		smtp: service,
	})
	smtpDnsModalApi.open()
}

const handleDelete = (service: SmtpService) => {
	confirm({
		title: t('smtp.delete.title'),
		content: t('smtp.delete.confirm', { name: service.smtp_name }),
		onConfirm: async () => {
			await deleteSmtp({ id: service.id })
			getCardList()
		},
	})
}

getCardList()
</script>

<style lang="scss" scoped></style>
