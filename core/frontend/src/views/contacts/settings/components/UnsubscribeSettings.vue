<template>
	<bt-form class="subscribe-settings">
		<n-form-item :label="$t('contacts.settings.unsubscribeSettings.subject')">
			<div class="w-420px">
				<n-input v-model:value="form.unsubscribe_subject"></n-input>
			</div>
		</n-form-item>
		<n-form-item :label="$t('contacts.settings.unsubscribeSettings.redirectLink')">
			<div class="w-420px">
				<n-input v-model:value="form.unsubscribe_redirect_url"></n-input>
			</div>
		</n-form-item>
		<n-form-item>
			<template #label>
				<span class="mr-16px">{{ $t('contacts.settings.unsubscribeSettings.emailPage') }}</span>
				<n-switch
					v-model:value="form.send_unsubscribe_email"
					:checked-value="1"
					:unchecked-value="0">
				</n-switch>
			</template>
			<div class="flex-1 w-auto">
				<div class="setting-description mb-8px">
					<p>
						{{ $t('contacts.settings.subscribeSettings.welcomeEmail.sendThroughTip') }}
						<n-tag size="small">{{ sender }}</n-tag>
						{{ $t('contacts.settings.subscribeSettings.welcomeEmail.mailboxTip') }}
					</p>
					<p>
						{{ $t('contacts.settings.unsubscribeSettings.enabledDescription') }}
					</p>
				</div>
				<editor v-model:value="form.unsubscribe_mail_html"></editor>
			</div>
		</n-form-item>
		<n-form-item :show-label="false">
			<n-button size="large" type="primary" @click="handleSave">
				{{ $t('common.actions.save') }}
			</n-button>
		</n-form-item>
	</bt-form>
</template>

<script lang="ts" setup>
import { saveUnsubscribeSetting } from '@/api/modules/contacts/group'
import { useContext } from '../hooks/useContext'
import Editor from './Editor.vue'

const { groupInfo, getInfo } = useContext()

const sender = ref('--')

const form = reactive({
	group_id: 0,
	send_unsubscribe_email: 0,
	unsubscribe_subject: '',
	unsubscribe_redirect_url: '',
	unsubscribe_mail_html: '',
	unsubscribe_mail_drag: '',
})

const handleSave = async () => {
	await saveUnsubscribeSetting(toRaw(form))
	getInfo()
}

watchEffect(() => {
	if (groupInfo.value) {
		form.group_id = groupInfo.value.id
		form.unsubscribe_subject = groupInfo.value.unsubscribe_subject
		form.unsubscribe_redirect_url = groupInfo.value.unsubscribe_redirect_url
		form.send_unsubscribe_email = groupInfo.value.send_unsubscribe_email
		form.unsubscribe_mail_html = groupInfo.value.unsubscribe_mail_html
		form.unsubscribe_mail_drag = groupInfo.value.unsubscribe_mail_drag
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
	line-height: 24px;
	color: var(--color-text-2);
}
</style>
