<template>
	<modal :title="$t('contacts.suspend.scan.title')" width="480" confirm-text="Scan">
		<div class="pt-12px">
			<bt-form ref="formRef" :form="form" :rules="rules">
				<n-form-item label="Group" path="group_id">
					<n-select v-model:value="form.group_id" :options="groupOptions" />
				</n-form-item>
				<n-form-item label="Method">
					<n-radio-group v-model:value="form.oper">
						<div class="h-32px flex items-center">
							<n-radio :value="1">{{ $t('contacts.suspend.scan.methods.noOperation') }}</n-radio>
						</div>
						<div class="h-32px flex items-center">
							<n-radio :value="2">{{
								$t('contacts.suspend.scan.methods.addToExceptionTable')
							}}</n-radio>
						</div>
						<div class="h-32px flex items-center">
							<n-radio :value="3">{{
								$t('contacts.suspend.scan.methods.deleteFromGroup')
							}}</n-radio>
						</div>
					</n-radio-group>
				</n-form-item>
			</bt-form>
		</div>
	</modal>
</template>

<script lang="ts" setup>
import { FormRules, SelectOption } from 'naive-ui'
import { isObject } from '@/utils'
import { useModal } from '@/hooks/modal/useModal'
import { scanGroup } from '@/api/modules/contacts/suspend'
import { getGroupAll } from '@/api/modules/contacts/group'
import type { Group } from '../../group/types/base'

const { t } = useI18n()

const formRef = useTemplateRef('formRef')

const form = reactive({
	group_id: null as number | null,
	oper: 1,
})

const rules: FormRules = {
	group_id: {
		trigger: 'change',
		validator: () => {
			if (!form.group_id) {
				return new Error(t('contacts.suspend.scan.form.groupRequired'))
			}
			return true
		},
	},
}

const groupOptions = ref<SelectOption[]>([])

const getGroupOptions = async () => {
	const res = await getGroupAll()
	if (isObject<{ list: Group[] }>(res)) {
		groupOptions.value = res.list.map(item => ({
			label: item.name,
			value: item.id,
		}))
	}
}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			getGroupOptions()
		} else {
			form.group_id = null
			form.oper = 1
		}
	},
	onConfirm: async () => {
		await formRef.value?.validate()
		await scanGroup({
			group_id: form.group_id || 0,
			oper: form.oper,
		})
		setTimeout(() => {
			const { showLogs } = modalApi.getState<{ showLogs: () => void }>()
			showLogs()
		}, 1500)
	},
})
</script>

<style lang="scss" scoped></style>
