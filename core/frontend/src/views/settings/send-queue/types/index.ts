export type SendQueue = {
	queue_id: string
	sender: string
	recipients: any
	arrival_time: number
	delay_reason: string
	message_size: number
	queue_name: string
	forced_expire: boolean
	recipient: string
}
