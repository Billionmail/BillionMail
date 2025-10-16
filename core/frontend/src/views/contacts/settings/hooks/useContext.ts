import { GroupInfo } from '../types/base'

type Instance = {
	groupInfo: Ref<GroupInfo | null>
	getInfo: () => Promise<void>
}

const key = Symbol('group-settings')

export function createContext(instance: Instance) {
	provide(key, instance)
}

export function useContext(): Instance {
	return inject(key) as Instance
}
