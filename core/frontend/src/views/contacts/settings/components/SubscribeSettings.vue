<template>
	<bt-form class="subscribe-settings">
		<n-form-item :label="$t('contacts.settings.subscribeSettings.listType.label')">
			<div class="w-200px">
				<n-select
					v-model:value="form.double_optin"
					:options="listTypeOptions"
					:placeholder="$t('contacts.settings.subscribeSettings.listType.placeholder')">
				</n-select>
			</div>
		</n-form-item>
		<n-form-item
			v-if="form.double_optin === 1"
			:label="$t('contacts.settings.subscribeSettings.confirmEmail.subject')">
			<div class="w-420px">
				<n-input v-model:value="form.confirm_subject"></n-input>
			</div>
		</n-form-item>
		<n-form-item
			v-if="form.double_optin === 1"
			:label="$t('contacts.settings.subscribeSettings.confirmEmail.redirectLink')">
			<div class="flex-1">
				<div class="setting-description mb-8px">
					{{ $t('contacts.settings.subscribeSettings.confirmEmail.redirectDescription') }}
				</div>
				<div class="w-420px">
					<n-input v-model:value="form.confirm_url"></n-input>
				</div>
			</div>
		</n-form-item>
		<n-form-item
			v-if="form.double_optin === 1"
			:label="$t('contacts.settings.subscribeSettings.confirmEmail.emailContent')">
			<div class="flex-1">
				<div class="setting-description mb-8px">
					<p>
						<span>
							{{ $t('contacts.settings.subscribeSettings.confirmEmail.emailTip1') }}
						</span>
						<n-tag size="small"> {{ `\{\{ ConfirmURL . \}\}` }} </n-tag>
						<span>{{ $t('contacts.settings.subscribeSettings.confirmEmail.emailTip2') }}</span>
					</p>
				</div>
				<editor v-model:value="form.confirm_mail_html"></editor>
			</div>
		</n-form-item>
		<n-form-item :label="$t('contacts.settings.subscribeSettings.welcomeEmail.subject')">
			<div class="w-420px">
				<n-input v-model:value="form.welcome_subject"></n-input>
			</div>
		</n-form-item>
		<n-form-item :label="$t('contacts.settings.subscribeSettings.welcomeEmail.redirectLink')">
			<div class="flex-1">
				<div class="setting-description mb-8px">
					{{ $t('contacts.settings.subscribeSettings.welcomeEmail.redirectDescription') }}
				</div>
				<div class="w-420px">
					<n-input v-model:value="form.success_url"></n-input>
				</div>
			</div>
		</n-form-item>
		<n-form-item>
			<template #label>
				<span class="mr-16px">
					{{ $t('contacts.settings.subscribeSettings.welcomeEmail.emailContent') }}
				</span>
				<n-switch v-model:value="form.send_welcome_email" :checked-value="1" :unchecked-value="0">
				</n-switch>
			</template>
			<div class="flex-1">
				<div class="setting-description mb-8px">
					<p>
						{{ $t('contacts.settings.subscribeSettings.welcomeEmail.sendThroughTip') }}
						<n-tag size="small">{{ sender }}</n-tag>
						{{ $t('contacts.settings.subscribeSettings.welcomeEmail.mailboxTip') }}
					</p>
					<p>
						{{ $t('contacts.settings.subscribeSettings.welcomeEmail.enabledDescription') }}
					</p>
					<p>
						<span>
							{{ $t('contacts.settings.subscribeSettings.welcomeEmail.templateVariablesTip') }}
						</span>
						<n-tag size="small">{{ `\{\{ .Subscriber.Email \}\}` }}</n-tag>
						<span>, </span>
						<n-tag size="small">{{ `\{\{ .Subscriber.name \}\}` }}</n-tag>
						<span> ...</span>
					</p>
				</div>
				<editor v-model:value="form.welcome_mail_html"></editor>
			</div>
		</n-form-item>
		<n-form-item :label="$t('contacts.settings.subscribeSettings.alreadySubscribed.redirectLink')">
			<div class="flex-1">
				<div class="setting-description mb-8px"></div>
				<div class="w-420px">
					<n-input v-model:value="form.already_url"></n-input>
				</div>
			</div>
		</n-form-item>
		<n-form-item :show-label="false">
			<n-button size="large" type="primary" @click="handleSave">
				{{ $t('common.actions.save') }}
			</n-button>
		</n-form-item>
	</bt-form>
</template>

<script setup lang="ts">
import { SelectOption } from 'naive-ui'
import { saveSubscribeSetting } from '@/api/modules/contacts/group'
import { useContext } from '../hooks/useContext'

import Editor from './Editor.vue'

const { t } = useI18n()

const sender = ref('--')

const form = reactive({
	group_id: 0,
	double_optin: 1,
	send_welcome_email: 1,
	welcome_subject: '',
	thank_you_subject: '',
	welcome_mail_html: '',
	welcome_mail_drag: '',
	success_url: '',
	confirm_subject: '',
	confirm_mail_html: '',
	confirm_mail_drag: '',
	confirm_url: '',
	already_url: '',
})

// 选项数据
const listTypeOptions: SelectOption[] = [
	{ label: t('contacts.settings.subscribeSettings.listType.options.doubleOptin'), value: 1 },
	{ label: t('contacts.settings.subscribeSettings.listType.options.singleOptin'), value: 0 },
]

const { groupInfo, getInfo } = useContext()

const handleSave = async () => {
	await saveSubscribeSetting(toRaw(form))
	getInfo()
}

watchEffect(() => {
	if (groupInfo.value) {
		form.group_id = groupInfo.value.id
		form.double_optin = groupInfo.value.double_optin
		form.welcome_subject = groupInfo.value.welcome_subject
		form.send_welcome_email = groupInfo.value.send_welcome_email
		form.welcome_mail_html = groupInfo.value.welcome_mail_html
		form.welcome_mail_drag = groupInfo.value.welcome_mail_drag
		form.success_url = groupInfo.value.success_url
		form.confirm_subject = groupInfo.value.confirm_subject
		form.confirm_mail_html = groupInfo.value.confirm_mail_html
		form.confirm_mail_drag = groupInfo.value.confirm_mail_drag
		form.confirm_url = groupInfo.value.confirm_url
		form.already_url = groupInfo.value.already_url
		sender.value = groupInfo.value.sender
	}
})
</script>

<style lang="scss" scoped>
.subscribe-settings {
	width: 80%;
	min-width: 1000px;
}

.setting-description {
	line-height: 20px;
	color: #666;
}

.action-buttons {
	width: 100%;
	padding: 23px 24px;
	background-color: var(--color-bg-1);
	border-top: 1px solid var(--color-border-1);
}
</style>
