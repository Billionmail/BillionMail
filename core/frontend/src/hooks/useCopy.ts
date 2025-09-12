import { Message } from '@/utils'
import { useClipboard } from '@vueuse/core'
import i18n from '@/i18n'

export const useCopy = () => {
	const { t } = i18n.global

	const { copy, isSupported, copied } = useClipboard({
		legacy: true,
	})

	const copyText = async (value: string, showSuccess = true) => {
		if (!value) {
			Message.error(t('common.useCopy.noText'))
			return
		}

		if (isSupported.value) {
			await copy(value)
			if (showSuccess) Message.success(t('common.useCopy.success'))
		} else {
			Message.error(t('common.useCopy.failed'))
		}
	}

	return {
		copied,
		copyText,
	}
}
