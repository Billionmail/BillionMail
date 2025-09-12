export interface Template {
	id: number
	temp_name: string
	add_type: number
	html_content: string
	drag_data: string
	create_time: number
	update_time: number
	chat_id?:string
}

export interface TemplateParams {
	page: number
	page_size: number
	keyword: string
}
