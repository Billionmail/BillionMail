export interface MailBoxParams {
	page: number
	page_size: number
	keyword: string
	domain: string | null
}

export interface MailBox {
	name: string
	username: string
	password: string
	password_encode: string
	full_name: string
	is_admin: number
	maildir: string
	mx: string
	quota: number
	local_part: string
	domain: string
	create_time: number
	update_time: number
	active: number
}
