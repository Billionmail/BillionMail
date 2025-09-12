import type { RouteRecordRaw } from 'vue-router'
import { Layout } from '@/router/constant'

export default {
	path: '/template',
	component: Layout,
	meta: {
		sort: 3,
		title: 'template',
		key: 'template',
		titleKey: 'layout.menu.template',
	},
	children: [
		{
			path: '/template',
			name: 'template',
			component: () => import('@/views/template/index.vue'),
		},
		{
			path: 'ai-template/:chatId',
			name: 'ai-template',
			component: () => import('@/views/template/pages/AITemplate/index.vue'),
		},
	],
} as RouteRecordRaw
