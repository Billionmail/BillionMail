export interface GroupInfo {
	id: number
	name: string
	description: string
	create_time: number
	update_time: number
	token: string
	double_optin: number
	welcome_subject: string
	send_welcome_email: number
	welcome_mail_html: string
	welcome_mail_drag: string
	confirm_subject: string
	confirm_mail_html: string
	confirm_mail_drag: string
	success_url: string
	confirm_url: string
	already_url: string
	sender: string
	subscribe_form: string
	total_count: number
	active_count: number
	unsubscribe_count: number
	subscribe_link: string
}
