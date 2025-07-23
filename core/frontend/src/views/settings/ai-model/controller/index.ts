import { instance } from '@/api'
import { Model, ModelStore, Provider } from '../dto'
import { confirm } from '@/utils'
export const instanceOptions = {
	fetchOptions: {
		loading: 'Loading... Please wait.',
		successMessage: true,
	},
}

/**
 * @description Get provider list
 */
export async function getProviderList(modelStore: ModelStore) {
	const { providerList, currentProvider } = modelStore
	try {
		const res = (await instance.post('/askai/supplier/list')) as Provider[]
		providerList.value = res
		if (res.length) {
			currentProvider.value = res[0]
			await getModelList(currentProvider.value.supplierName, modelStore)
		}
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Get model list
 */
export async function getModelList(supplierName: string, modelStore: ModelStore) {
	const { modelList, configurationLoading } = modelStore
	try {
		configurationLoading.value = true
		const res = (await instance.post('/askai/supplier/models', { supplierName })) as Model[]
		modelList.value = res
	} catch (error) {
		console.warn(error)
	} finally {
		configurationLoading.value = false
	}
}

/***
 * @description Confirm add provider
 */
export async function confirmAddProvider(modelStore: ModelStore) {
	const { addProviderFormData, addProviderFormDataRef, addProviderRef } = modelStore
	try {
		const checkStatus = await checkProviderConfig(modelStore)
		if (!checkStatus) return false
		await addProviderFormDataRef.value?.validate()
		await instance.post('/askai/supplier/add_supplier', addProviderFormData.value, instanceOptions)
		addProviderRef.value.close()
		await getProviderList(modelStore)
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Confirm add model
 */
export async function confirmAddModel(modelStore: ModelStore) {
	const { currentProvider, addModelFormData, addModelFormRef, addModelRef } = modelStore
	try {
		// console.log(addModelFormData)
		await addModelFormRef.value?.validate()
		await instance.post(
			'/askai/supplier/add_model',
			{ ...addModelFormData.value, supplierName: currentProvider.value.supplierName },
			instanceOptions
		)
		await getModelList(currentProvider.value.supplierName, modelStore)
		addModelRef.value.close()
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Get provider configuration
 */
export async function getProviderConfiguration(modelStore: ModelStore) {
	const { currentProvider, providerList } = modelStore
	try {
		const res = (await instance.post(
			'/askai/supplier/get_supplier_config',
			{ supplierName: currentProvider.value.supplierName },
			instanceOptions
		)) as Provider
		const findProvider = providerList.value.find(
			item => item.supplierName == currentProvider.value.supplierName
		)
		if (findProvider) {
			findProvider.apiKey = res.apiKey
			findProvider.baseUrl = res.baseUrl
		}
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Change provider status
 */
export async function changeProviderStatus(status: boolean, modelStore: ModelStore) {
	const { currentProvider } = modelStore
	try {
		await instance.post(
			'/askai/supplier/set_supplier_status',
			{ supplierName: currentProvider.value.supplierName, status },
			instanceOptions
		)
		currentProvider.value.status = status
		getModelList(currentProvider.value.supplierName, modelStore)
	} catch (error) {
		currentProvider.value.status = !status
		console.warn(error)
	}
}

/**
 * @description Check provider api configuration
 */
export async function checkProviderApiConfiguration(modelStore: ModelStore) {
	const { currentProvider } = modelStore
	try {
		await instance.post(
			'/askai/supplier/testing',
			{
				supplierName: currentProvider.value.supplierName,
				baseUrl: currentProvider.value.baseUrl,
				apiKey: currentProvider.value.apiKey,
			},
			instanceOptions
		)
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Set provider configuration
 */
export async function setProviderConfiguration(modelStore: ModelStore) {
	const { currentProvider } = modelStore
	try {
		await instance.post(
			'/askai/supplier/set_supplier_config',
			{
				supplierName: currentProvider.value.supplierName,
				baseUrl: currentProvider.value.baseUrl,
				apiKey: currentProvider.value.apiKey,
			},
			instanceOptions
		)
		changeProviderStatus(true, modelStore)
	} catch (error) {
		console.warn(error)
	}
}

/**
 * @description Set model status
 */
export async function setModelStatus(model: Model, status: boolean, modelStore: ModelStore) {
	const { currentProvider } = modelStore
	try {
		await instance.post(
			'/askai/supplier/set_model_status',
			{
				supplierName: currentProvider.value.supplierName,
				modelId: model.modelId,
				status,
			},
			instanceOptions
		)
	} catch (error) {
		model.status = !status
		console.warn(error)
	}
}

/**
 * @description Remove provider
 */
export async function removeProvider(modelStore: ModelStore) {
	const { currentProvider } = modelStore
	confirm({
		title: 'Notice',
		content: `Are you sure to remove the provider "${currentProvider.value.supplierName}"?`,
		onConfirm: async () => {
			try {
				await instance.post(
					'/askai/supplier/remove_supplier',
					{ supplierName: currentProvider.value.supplierName },
					instanceOptions
				)
				await getProviderList(modelStore)
			} catch (error) {
				console.warn(error)
			}
		},
	})
}

/**
 * @description Check provider configuration
 */
export async function checkProviderConfig(store: ModelStore) {
	const { addProviderFormData } = store
	try {
		await instance.post('/askai/supplier/testing', addProviderFormData.value)
		return true
	} catch (error) {
		console.warn(error)
		return false
	}
}

/**
 * @description Remove model
 */
export async function removeModel(model: Model, modelStore: ModelStore) {
	confirm({
		title: 'Notice',
		content: `Are you sure to remove the Model "${model.title}"?`,
		onConfirm: async () => {
			try {
				await instance.post(
					'/askai/supplier/remove_model',
					{ supplierName: model.supplierName, modelId: model.modelId },
					instanceOptions
				)
				await getModelList(model.supplierName,modelStore)
			} catch (error) {
				console.warn(error)
			}
		},
	})
}
