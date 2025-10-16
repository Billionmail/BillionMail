<template>
	<div class="smtp-card relative rounded-8px p-16px shadow-sm">
		<div class="flex items-center mb-16px">
			<div class="flex items-center flex-1">
				<div class="w-32px h-32px flex items-center justify-center rounded-full bg-primary-100">
					<img :src="iconSrc" class="w-full h-full object-contain"></img>
				</div>
				<div class="ml-16px flex items-center gap-10px flex-1 min-w-0">
					<div class="text-18px font-600 truncate">{{ service.smtp_name }}</div>
					<smtp-status :value="service.smtp_status.status"></smtp-status>
				</div>
			</div>
			<div class="ml-8px">
				<n-switch :value="service.active" :checked-value="1" :unchecked-value="0" @update:value="handleUpdateActive"></n-switch>
			</div>
		</div>
		<div class="smtp-desc">{{ service.remark }}</div>
		<div class="smtp-info">
			<div class="info-row">
				<span class="info-label">{{ $t('smtp.card.domain') }}：</span>
				<span class="info-value flex flex-wrap gap-8px">
					<n-tag v-for="domain in service.sender_domains" :key="domain" :bordered="false">{{ domain }}</n-tag>
					<n-tag v-if="service.check_spf === 1" type="warning" class="cursor-pointer" :bordered="false" @click="handleShowDns">
						<div class="flex items-center gap-4px">
							<i class="i-carbon:warning-filled text-16px"></i>
							<span>{{ $t('smtp.card.dnsUpdateRequired') }}</span>
						</div>
					</n-tag>
				</span>
			</div>
			<div class="info-row">
				<span class="info-label">{{ $t('smtp.card.server') }}：</span>
				<span class="info-value">
					<n-ellipsis>{{ service.relay_host }}</n-ellipsis>
				</span>
			</div>
			<div class="info-row">
				<span class="info-label">{{ $t('smtp.card.port') }}：</span>
				<span class="info-value">{{ service.relay_port }}</span>
			</div>
			<div class="info-row">
				<span class="info-label">{{ $t('smtp.card.username') }}：</span>
				<span class="info-value truncate">{{ service.auth_user }}</span>
			</div>
		</div>
		<div class="action-buttons">
			
			<n-button secondary class="action-btn" @click="handleEdit">
				<template #icon>
					<i class="i-mdi-edit"></i>
				</template>
			</n-button>
			<n-button secondary class="action-btn" @click="handleDelete">
				<template #icon>
					<i class="i-mdi-delete"></i>
				</template>
			</n-button>
		</div>
	</div>
</template>

<script lang="ts" setup>
import { editSmtp } from '@/api/modules/smtp'
import { SmtpService } from '../types/base'
import SmtpStatus from './SmtpStatus.vue'
import GmailImg from '@/assets/images/smtp/gmail.svg'
import MailgunImg from '@/assets/images/smtp/mailgun.svg'
import AwsImg from '@/assets/images/smtp/aws-ses.svg'
import SendgridImg from '@/assets/images/smtp/sendgrid.svg'
import LocalhostImg from '@/assets/images/smtp/localhost.svg'
import CustomImg from '@/assets/images/smtp/custom.svg'

const { service } = defineProps({
	service: {
		type: Object as PropType<SmtpService>,
		required: true,
	}
})

const emit = defineEmits<{
	edit: [service: SmtpService],
	delete: [service: SmtpService],
	showDns: [service: SmtpService]
}>()

const iconSrc = computed(() => {
	switch (service.smtp_name) {
		case 'Gmail':
			return GmailImg
		case 'Mailgun':
			return MailgunImg
		case 'AWS SES':
			return AwsImg
		case 'SendGrid':
			return SendgridImg
		case 'custom':
			return CustomImg
		case 'local':
			return LocalhostImg
		default:
			return CustomImg
	}
})

const handleEdit = () => {
	emit('edit', service)
}

const handleDelete = () => {
	emit('delete', service)
}

const handleShowDns = () => {
	emit('showDns', service)
}

const handleUpdateActive = async (val: number) => {
	await editSmtp({
		id: service.id,
		active: val,
	})
	service.active = val
}
</script>

<style lang="scss" scoped>
.smtp-card {
	min-height: 180px;
	transition: all 0.3s ease;
	border: 1px solid rgba(0, 0, 0, 0.05);
	background-color: var(--color-bg-1);

	&:hover {
		box-shadow: 0 6px 16px rgba(0, 0, 0, 0.12);
		transform: translateY(-2px);
	}
}

.smtp-desc {
	margin-bottom: 16px;
	font-size: 14px;
	color: var(--color-text-2);
}

.smtp-info {
	margin-bottom: 16px;
	.info-row {
		display: flex;
		flex-wrap: wrap;
		line-height: 20px;
		font-size: 13px;
		& + .info-row {
			margin-top: 8px;
		}

		.info-label {
			color: var(--color-text-2);
			min-width: 120px;
			font-weight: 400;
		}

		.info-value {
			flex: 1;
			width: 0;
			color: var(--color-text-1);
			font-weight: 500;
		}
	}
}

.action-buttons {
	display: flex;
	justify-content: flex-end;
	gap: 12px;
	
	.action-btn {
		--n-width: 32px;
		--n-height: 32px;
		--n-padding: 0;
	}
}
</style>
