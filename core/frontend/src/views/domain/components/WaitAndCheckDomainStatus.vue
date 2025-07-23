<template>
    <n-modal v-model:show="show" :close-on-esc="false" :mask-closable="false">
        <n-card style="width: auto;">
            <div class="flex justify-start gap-2.5 bg-transparent items-center">
                <i class="i-svg-spinners:bars-scale text-[var(--color-primary-1)] text-6"></i>
                <span class="flex items-center text-4">{{ $t("domain.waitAndCheckDomainStatus.loading") }}</span>
            </div>
        </n-card>
    </n-modal>

    <!-- Create Ai template -->
    <CreateTplModal ref="createTplModal" :only-ai="true" />
</template>

<script setup lang="ts">
import CreateTplModal from '@/views/template/components/CreateTplModal.vue'
import { useGlobalStore } from '@/store';
import { instance } from '@/api';
import { Message } from '@/utils';
const { t } = useI18n()
const show = ref(false)
const globalStore = useGlobalStore()
const createTplModal = ref()

function open(domain: string, callback?: () => void) {
    checkStatus(domain, callback)
    globalStore.domainSource = domain
    show.value = true
}
function close() {
    show.value = false
}
function checkStatus(domain: string, callback?: () => void) {

    let timer = setInterval(async () => {
        const statusFlag = await getBaseInfoAndCheckStatus(domain)
        if (statusFlag) {
            Message.success(t("domain.waitAndCheckDomainStatus.success"))
            callback && callback()
            close()
            clearInterval(timer)
            createTplModal.value.open()
        }
    }, 1000)
}

/**
 * @description Get base info and check status
 */
async function getBaseInfoAndCheckStatus(domain: string) {
    try {
        const res = await instance.post("/askai/project/get_base_info", { domain }) as Record<string, any>
        if (res.update_time) {
            return true
        } else {
            return false
        }
    } catch (error) {
        console.warn(error)
        Message.error(t("domain.waitAndCheckDomainStatus.error"))
        return false
    }
}
defineExpose({
    open,
    close,
    checkStatus,
})

</script>

<style scoped></style>