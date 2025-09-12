export type SmtpServiceType = 'gmail' | 'sendgrid' | 'local' | 'custom'

export interface SmtpService {
	id: number
	remark: string
	sender_domain: string
	sender_domains: string[]
	relay_host: string
	relay_port: string
	auth_user: string
	auth_password: string
	ip: string
	host: string
	active: number
	create_time: number
	update_time: number
	auth_method: string
	tls_protocol: string
	skip_tls_verify: number
	helo_name: string
	smtp_name: string
	header_json: string
	max_concurrency: number
	max_retries: number
	max_idle_time: string
	max_wait_time: string
	rtype: string
	check_spf: number
	spf_record: {
		type: string
		host: string
		value: string
	}
	spf_records: {
		check: number
		dns_record: {
			type: string
			host: string
			value: string
		}
	}[]
	smtp_status: {
		status: boolean
		msg: string
	}
}
