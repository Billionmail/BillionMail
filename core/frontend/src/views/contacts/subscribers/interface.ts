export interface Subscriber {
	id: number
	email: string
	group_id: number
	active: number
	status: number
	task_id: number
	create_time: number
	group_name: string
	attribs: Record<string, string> | null
	groups: Array<{
		id: number
		name: string
	}>
}

export interface SubscriberParams {
	page: number
	page_size: number
	group_id: number
	keyword: string
	active: number
}

export interface SubscriberTrend {
	count: number
	month: string
}
