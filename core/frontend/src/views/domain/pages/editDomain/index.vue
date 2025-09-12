<template>
	<div class="wrapper">
		<n-breadcrumb class="mb-20px">
			<n-breadcrumb-item>
				<router-link to="/domain">{{ $t('domain.edit.breadcrumb.domain') }}</router-link>
			</n-breadcrumb-item>
			<n-breadcrumb-item>{{ domain }}</n-breadcrumb-item>
			<n-breadcrumb-item>{{ $t('domain.edit.breadcrumb.editDomain') }}</n-breadcrumb-item>
		</n-breadcrumb>

		<!-- Content tabs -->
		<div class="content-tabs">
			<div
				v-for="(item, index) in menuList"
				:key="index"
				:class="['tab-item', { active: activeTab == item }]"
				@click="switchToTab(item)">
				<span>{{ getTabLabel(item) }}</span>
			</div>
		</div>
		<div class="dynamic-content">
			<n-scrollbar style="height: 100%">
				<component :is="contentMap.get(activeTab)" />
			</n-scrollbar>
		</div>

		<div v-if="!['Domain Configuration', 'Sitemap'].includes(activeTab)" class="footer-tool">
			<n-button type="primary" @click="handleSwitchSave">
				<template #icon>
					<i class="i-mingcute:save-2-line text-5"></i>
				</template>
				{{ $t('domain.edit.save') }}
			</n-button>
		</div>
	</div>
</template>

<script setup lang="ts">
import { onBeforeRouteLeave } from 'vue-router'
import { updateDomain, resetAllApiStatus } from './controller/domainConfiguration.controller'
import { updateProjectDetail } from './controller/projectDetail.controller'
import { updateCompanyProfile } from './controller/companyProfile.controller'
import { updateStylingInfo } from './controller/styling.controller'
import { updateTypography } from './controller/typography.controller'
// import {} from "./controller/sitemap.controller"
import { updateFooterSettingsInfo } from './controller/footerSettings.controller'
import { updateAiSettingsInfo } from './controller/aiSettings.controller'
import { getEditDomainStoreData } from './store'
import { Message } from '@/utils'
const { createdBrandInfo } = getEditDomainStoreData()
const DomainConfiguration = defineAsyncComponent(
	() => import('./components/DomainConfiguration.vue')
)
const ProjectDetails = defineAsyncComponent(() => import('./components/ProjectDetails.vue'))
const CompanyProile = defineAsyncComponent(() => import('./components/CompanyProfile.vue'))
const Styling = defineAsyncComponent(() => import('./components/Styling.vue'))
// const Typography = defineAsyncComponent(() => import('./components/Typography.vue'))
const Sitemap = defineAsyncComponent(() => import('./components/Sitemap.vue'))
const FooterSettings = defineAsyncComponent(() => import('./components/FooterSettings.vue'))
// const AISettings = defineAsyncComponent(() => import('./components/AISettings.vue'))

const { t } = useI18n()

const menuList = ref([
	'Domain Configuration',
	'Project Details',
	'Company Profile',
	'Styling',
	'Sitemap',
	'Footer Settings',
	// 'AI Settings',
])

// const dynamicMenuList = computed(() => {
// 	if (createdBrandInfo.value) {
// 		return menuList.value
// 	} else {
// 		return menuList.value.filter(item => item == 'Domain Configuration')
// 	}
// })

const activeTab = ref('Domain Configuration')

const contentMap = new Map([
	['Domain Configuration', DomainConfiguration],
	['Project Details', ProjectDetails],
	['Company Profile', CompanyProile],
	['Styling', Styling],
	['Sitemap', Sitemap],
	['Footer Settings', FooterSettings],
	// ['AI Settings', AISettings],
])

const route = useRoute()
const domain = route.params.domain as string

/**
 * @description Get tab label with i18n
 */
function getTabLabel(tabKey: string): string {
	const keyMap: Record<string, string> = {
		'Domain Configuration': 'domain.edit.tabs.domainConfiguration',
		'Project Details': 'domain.edit.tabs.projectDetails',
		'Company Profile': 'domain.edit.tabs.companyProfile',
		Styling: 'domain.edit.tabs.styling',
		Sitemap: 'domain.edit.tabs.sitemap',
		'Footer Settings': 'domain.edit.tabs.footerSettings',
		'AI Settings': 'domain.edit.tabs.aiSettings',
	}
	return t(keyMap[tabKey] || tabKey)
}

/**
 * @description Switch for handle save
 */
function handleSwitchSave() {
	switch (activeTab.value) {
		case 'Domain Configuration':
			updateDomain()
			break
		case 'Project Details':
			updateProjectDetail(domain)
			break
		case 'Company Profile':
			updateCompanyProfile(domain)
			break
		case 'Styling':
			updateStylingInfo(domain)
			break
		case 'Typography':
			updateTypography(domain)
			break
		case 'Sitemap':
			break
		case 'Footer Settings':
			updateFooterSettingsInfo(domain)
			break
		case 'AI Settings':
			updateAiSettingsInfo(domain)
			break
	}
}

/**
 * Reset all api status when router leave
 */
onBeforeRouteLeave(resetAllApiStatus)

/**
 * @description Switch to tab
 */
function switchToTab(tab: string) {
	if (tab == 'Domain Configuration') {
		activeTab.value = tab
	} else {
		if (createdBrandInfo.value) {
			activeTab.value = tab
		} else {
			Message.info(t('domain.edit.common.noBrandInfo'))
		}
	}
}
</script>

<style scoped lang="scss">
@use '@/styles/index' as base;

.wrapper {
	display: grid;
	grid-template-rows: 40px 45px 1fr 80px;
	height: calc(100% - 48px);
	box-sizing: border-box;
	padding: 24px;
}

.footer-tool {
	position: absolute;
	bottom: 0px;
	left: 0;
	background: #fff;
	width: 100%;
	height: 80px;
	@include base.row-flex;
	justify-content: flex-start;
	align-items: center;
	padding: 0 20px;
}

// page title
.page-tit {
	@include base.row-flex-start;
	margin-bottom: 20px;
	gap: 15px;

	.back-tool {
		color: var(--color-primary-1);
		@include base.row-flex-start;
		gap: 5px;
		cursor: pointer;
		@include base.transition-all;

		&:hover {
			color: var(--color-primary-3);
		}

		.back-btn {
			font-size: 18px;
		}
	}

	.tit-content {
		font-size: 18px;
		color: var(--color-text-1);
		font-weight: bold;
	}
}

// Content tabs
.content-tabs {
	width: 100%;
	height: 46px;
	border-bottom: 1px solid var(--color-border-1);
	@include base.row-flex-start;

	.tab-item {
		height: 100%;
		@include base.col-flex-center;
		font-size: 14px;
		padding: 0 20px;
		cursor: pointer;
		transition: 0.1s color ease-in-out;

		&:hover {
			color: var(--color-primary-1);
		}

		&.active {
			color: var(--color-primary-1);
			border-bottom: 2px solid var(--color-primary-1);
			margin-bottom: -2px;
		}
	}
}

// Dynamic content
.dynamic-content {
	height: calc(100vh - 240px);
	box-sizing: border-box;
	padding: 20px;
}
</style>
