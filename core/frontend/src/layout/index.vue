<template>
	<n-layout class="w-full h-full" has-sider>
		<sidebar></sidebar>
		<n-layout :content-style="{ position: 'relative', paddingTop: '48px' }" @scroll="handleScroll">
			<app-header :top="scrollTop"></app-header>
			<app-main></app-main>
		</n-layout>
	</n-layout>
	<div
		v-if="isMobile"
		v-show="mobileMenuOpen"
		class="mobile-sider-backdrop"
		@click="globalStore.closeMobileMenu()">
	</div>
</template>

<script lang="ts" setup>
import { storeToRefs } from 'pinia'
import { Sidebar, AppHeader, AppMain } from './components'
import { useGlobalStore } from '@/store'

const globalStore = useGlobalStore()
const { isMobile, mobileMenuOpen } = storeToRefs(globalStore)

const scrollTop = ref(0)

const handleScroll = (e: Event) => {
	scrollTop.value = (e.target as HTMLElement).scrollTop || 0
}
</script>

<style lang="scss" scoped>
.mobile-sider-backdrop {
	position: fixed;
	inset: 0;
	background: rgb(0 0 0 / 0.45);
	z-index: 1009;
}

// Naive UI's has-sider layout is a flex row, and flex items refuse to
// shrink below their content's natural width unless told otherwise. On
// mobile the sidebar is fixed/out-of-flow, but without this the content
// pane would still stretch to fit whatever the widest thing on the page
// wants (a filter bar, a table, etc.), forcing the entire app to scroll
// horizontally instead of the offending element reflowing on its own.
@media (max-width: 768px) {
	:deep(.n-layout-scroll-container) {
		min-width: 0;
	}
}
</style>
