interface ServerConfig {
	https: boolean
	address: string
	host: string
}

const serverConfig: Record<string, ServerConfig> = { 
	'192.168.66.66': {
		https: false,
		address: 'http://192.168.66.66:64325',
		host: '192.168.66.66',
	},
	'192.168.66.124': {
		https: true,
		address: 'https://192.168.66.124:82',
		host: '192.168.66.124',
	},
	'192.168.10.35': {
		https: true,
		address: 'https://192.168.10.35',
		host: '192.168.10.35',
	},
}

export default serverConfig
