import { FormInst } from "naive-ui"

export type Provider = {
    supplierTitle: string
    supplierName: string
    baseUrl: string
    baseUrlExample: string
    isUseUrlExample: boolean
    apiKey: string
    home: string
    help: string
    status: boolean
    icon:string
    sort:number
}

export type Model = {
    modelId:string
    supplierName: string
    capability: string[]
    title: string
    status:boolean
    max_tokens:number
}

export type AddProviderFormData = {
    supplierTitle: string
    supplierName: string
    baseUrl: string
    apiKey: string
}

export type AddModelFormData = {
    title: string
    modelId: string
    max_tokens: number
    capability: string[]
}

export type ModelStore = {
    providerList: Ref<Provider[]>
    modelList: Ref<Model[]>
    currentProvider: Ref<Provider>
    configurationLoading: Ref<boolean>
    addProviderFormData: Ref<AddProviderFormData>
    addProviderFormDataRef: Ref<FormInst | null | undefined>
    addProviderRef: Ref<any>
    addModelFormData: Ref<AddModelFormData>
    addModelFormRef: Ref<FormInst | null | undefined>
    addModelRef: Ref<any>
}