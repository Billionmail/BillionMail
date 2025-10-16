import { FormInst } from "naive-ui";
import { AddModelFormData, AddProviderFormData, Model, ModelStore, Provider } from "../dto";

export function useModelManagerStore(): ModelStore {
    const providerList = ref<Provider[]>([])
    const modelList = ref<Model[]>([])
    const addProviderRef = ref<any>()
    const currentProvider = ref<Provider>({
        supplierTitle: "",
        supplierName: "",
        baseUrl: "",
        baseUrlExample: "",
        isUseUrlExample: false,
        apiKey: "",
        home: "",
        help: "",
        status: false,
        icon: "",
        sort: 0
    })
    const configurationLoading = ref(false)
    const addProviderFormData = ref<AddProviderFormData>({
        supplierTitle: "",
        supplierName: "",
        baseUrl: "",
        apiKey: ""
    })
    const addProviderFormDataRef = ref<FormInst | null | undefined>()
    const addModelFormData = ref<AddModelFormData>({
        title: "",
        modelId: "",
        max_tokens: 8192,
        capability: ["llm"]
    })
    const addModelFormRef = ref<FormInst | null | undefined>()
    const addModelRef = ref<any>()

    return {
        providerList,
        modelList,
        addProviderRef,
        currentProvider,
        configurationLoading,
        addProviderFormData,
        addProviderFormDataRef,
        addModelFormData,
        addModelFormRef,
        addModelRef
    }
}