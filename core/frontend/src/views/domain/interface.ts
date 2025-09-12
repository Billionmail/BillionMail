export interface MailDomainParams {
	page: number
	page_size: number
	keyword: string
}

export interface MailDomain {
	domain: string
	a_record: string
	mailboxes: number
	mailbox_quota: number
	quota: number
	rate_limit: number
	create_time: number
	active: number
	default: number
	email: string
	hasbrandinfo: number
	urls: string[]
	dns_records: DomainDnsRecords
	cert_info: DomainCertInfo
	multi_ip_domains: DomainMultiIp | null
}

export interface DomainMultiIp {
	id: number
	domain: string
	outbound_ip: string
	network_name: string
	subnet: string
	postfix_ip: string
	aliases: string
	smtp_server_name: string
	active: number
	create_time: number
	update_time: number
	status: string
	repair_command: string
	utility_command: string
}

export type DomainDnsRecords = {
	[key: string]: {
		type: string
		host: string
		value: string
		valid: boolean
	}
}

export type DomainCertInfo = {
	subject: string
	issuer: string
	not_before: string
	not_after: string
	dns: string[]
	endtime: number
	key_pem: string
	cert_pem: string
}
