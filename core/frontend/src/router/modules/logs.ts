import { RouteRecordRaw } from 'vue-router'
import { Layout } from '@/router/constant'

const route: RouteRecordRaw = {
	path: '/logs',
	redirect: '/logs/operation',
	component: Layout,
	meta: { key: 'logs', title: 'Logs', titleKey: 'layout.menu.logs' },
	children: [
		{
			path: '/logs',
			redirect: '/logs/operation',
			name: 'Logs',
			component: () => import('@/views/logs/index.vue'),
			children: [
				{
					path: 'operation',
					name: 'Operation Logs',
					meta: { title: 'Operation logs', titleKey: '' },
					component: () => import('@/views/logs/operate/index.vue'),
				},
				{
					path: 'error',
					name: 'Error Logs',
					meta: { title: 'Error logs', titleKey: '' },
					component: () => import('@/views/logs/error/index.vue'),
				},
			],
		},
	],
}

export default route
