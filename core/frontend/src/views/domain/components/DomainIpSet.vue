<template>
	<modal :title="title" :width="500" :footer="false">
		<div class="pt-16px px-16px text-basic">
			<div class="flex justify-between items-center mb-16px">
				<div>{{ $t('domain.ipSet.dedicatedIp') }}{{ ip }}</div>
				<div class="flex items-center">
					{{ $t('domain.ipSet.configFile') }}
					<ip-status :status="configStatus"></ip-status>
				</div>
				<div class="flex items-center">
					{{ $t('domain.ipSet.connectionStatus') }}
					<ip-status :status="connectStatus"></ip-status>
				</div>
			</div>
			<n-alert class="mb-16px" type="warning" :show-icon="false" :bordered="false">
				{{ $t('domain.ipSet.warning') }}
			</n-alert>

			<n-spin size="small" :show="loading">
				<n-alert class="command-alert mb-16px" :show-icon="false" :bordered="false">
					{{ command || '--' }}
				</n-alert>
			</n-spin>

			<div class="flex justify-center gap-16px">
				<n-button type="primary" :loading="loading" :disabled="loading" @click="getCommand">
					{{ $t('domain.ipSet.getCommand') }}
				</n-button>
				<n-button @click="onCopyCommand">{{ $t('domain.ipSet.copyCommand') }}</n-button>
			</div>
		</div>

		<bt-modal
			v-model:show="showModal"
			:width="420"
			:title="$t('domain.ipSet.operationReminder')"
			:footer="false">
			<n-alert class="mb-16px" type="warning" :show-icon="false" :bordered="false">
				{{ $t('domain.ipSet.fixCommandTip') }}<br />"{{ fixCommand }}"
			</n-alert>
			<div class="flex justify-center">
				<n-button type="primary" @click="showModal = false">{{
					$t('domain.ipSet.understood')
				}}</n-button>
			</div>
		</bt-modal>
	</modal>
</template>

<script lang="ts" setup>
import { isObject, Message } from '@/utils'
import { useCopy } from '@/hooks/useCopy'
import { useModal } from '@/hooks/modal/useModal'
import { getDomainIpCommand } from '@/api/modules/domain'
import { MailDomain } from '../interface'
import IpStatus from './IpStatus.vue'

const { t } = useI18n()

const domain = ref('')

const ip = ref('')

const status = ref('')

const configStatus = computed(() => {
	if (status.value === 'failed') return 'failed'
	return 'applied'
})

const connectStatus = computed(() => {
	if (status.value === 'applied') return 'applied'
	return 'failed'
})

const title = computed(() => {
	return domain.value
		? t('domain.ipSet.titleWithDomain', { domain: domain.value })
		: t('domain.ipSet.title')
})

const loading = ref(false)

const isFetchCommand = ref(false)

const command = ref('')

const fixCommand = ref('')

const getCommand = async () => {
	try {
		loading.value = true
		const res = await getDomainIpCommand()
		if (isObject<{ command: string; fix_command: string }>(res)) {
			command.value = res.command
			fixCommand.value = res.fix_command
			isFetchCommand.value = true
		}
	} finally {
		loading.value = false
	}
}

const showModal = ref(false)

const { copyText } = useCopy()

const onCopyCommand = () => {
	if (!isFetchCommand.value) {
		Message.error(t('domain.ipSet.validation.getCommandFirst'))
		return
	}

	copyText(command.value, false)
	showModal.value = true
}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const { row } = modalApi.getState<{ row: MailDomain }>()
			domain.value = row.domain
			ip.value = row.multi_ip_domains?.outbound_ip || ''
			status.value = row.multi_ip_domains?.status || ''
		}
	},
})
</script>

<style lang="scss" scoped>
.command-alert {
	--n-color: var(--color-command);
	--n-content-text-color: #fff;
}
</style>
