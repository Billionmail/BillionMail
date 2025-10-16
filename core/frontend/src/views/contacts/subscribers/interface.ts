export interface Subscriber {
	id: number
	email: string
	group_id: number
	active: number
	status: number
	task_id: number
	create_time: number
	last_active_at: number
	group_name: string
	attribs: Record<string, string> | null
	tags: Array<{
		id: number
		name: string
	}>
}

export interface SubscriberParams {
	page: number
	page_size: number
	keyword: string
	group_id: number
	active: number
	last_active_status: number
	time_interval: number
	tags: number[]
}

export interface SubscriberTrend {
	count: number
	date: string
}
