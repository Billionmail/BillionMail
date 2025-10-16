export type Suspend = {
	id: number
	create_time: number
	recipient: string
	count: number
	status: string
	task_name: string
	state: number
	task_time: number
}

export type SuspendParams = {
	page: number
	page_size: number
	status: number
	keyword: string
}
