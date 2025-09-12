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
		address: 'https://192.168.66.124',
		host: '192.168.66.124',
	},
	'192.168.10.35': {
		https: true,
		address: 'https://192.168.10.35',
		host: '192.168.10.35',
	},
	'103.179.242.193': {
		https: true,
		address: 'https://103.179.242.193:4433',
		host: '103.179.242.193',
	},
}

export default serverConfig
