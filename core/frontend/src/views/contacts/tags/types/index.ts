export type TagParams = {
	keyword: string
	group_id: number
	page: number
	page_size: number
}

export type Tag = {
	id: number
	group_id: number
	name: string
	create_time: number
}
