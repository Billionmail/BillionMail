package askai

import (
	"billionmail-core/internal/service/public"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/gogf/gf/v2/frame/g"
)

const (
	SUPPLIER_CONFIG_PATH   = "../conf/supplier"
	SUPPLIER_TEMPLATE_PATH = SUPPLIER_CONFIG_PATH + "/template"
)

type Supplier struct {
	SupplierTitle   string `json:"supplierTitle"`
	SupplierName    string `json:"supplierName"`
	BaseUrl         string `json:"baseUrl"`
	BaseUrlExample  string `json:"baseUrlExample"`
	IsUseUrlExample bool   `json:"isUseUrlExample"`
	ApiKey          string `json:"apiKey"`
	Home            string `json:"home"`
	Help            string `json:"help"`
	Status          bool   `json:"status"`
	Sort            int    `json:"sort"`
	Icon            string `json:"icon"`
}

type ModelInfo struct {
	Title        string   `json:"title"`
	SupplierName string   `json:"supplierName"`
	ModelId      string   `json:"modelId"`
	MaxTokens    int      `json:"max_tokens"`
	Capability   []string `json:"capability"`
	Status       bool     `json:"status"`
}

var IsSyncTemplateToConfig = false

// SyncTemplateToConfig copies the template files from the SUPPLIER_TEMPLATE_PATH to the SUPPLIER_CONFIG_PATH.
func SyncTemplateToConfig() {
	if IsSyncTemplateToConfig {
		return
	}
	if !public.FileExists(SUPPLIER_TEMPLATE_PATH) {
		g.Log().Error(context.Background(), "Supplier template path does not exist: "+SUPPLIER_TEMPLATE_PATH, public.GetCwdPath())
		return
	}

	supplierTemplates, err := os.ReadDir(SUPPLIER_TEMPLATE_PATH)

	if err != nil {
		return
	}

	for _, supplier := range supplierTemplates {
		supplierName := supplier.Name()
		if supplierName == "" {
			continue
		}

		dstSupplierPath := SUPPLIER_CONFIG_PATH + "/" + supplierName
		if !public.FileExists(dstSupplierPath) {
			os.MkdirAll(dstSupplierPath, os.ModePerm)
		}

		srcConfigFile := SUPPLIER_TEMPLATE_PATH + "/" + supplierName + "/config.json"
		dstConfigFile := dstSupplierPath + "/config.json"
		if !public.FileExists(dstConfigFile) {
			fBody, err := os.ReadFile(srcConfigFile)
			if err != nil {
				continue
			}
			os.WriteFile(dstConfigFile, fBody, os.ModePerm)
		}

		srcModelsFile := SUPPLIER_TEMPLATE_PATH + "/" + supplierName + "/models.json"
		dstModelsFile := dstSupplierPath + "/models.json"
		if !public.FileExists(dstModelsFile) {
			fBody, err := os.ReadFile(srcModelsFile)
			if err != nil {
				continue
			}
			os.WriteFile(dstModelsFile, fBody, os.ModePerm)
		}

		srcEmbeddingFile := SUPPLIER_TEMPLATE_PATH + "/" + supplierName + "/embedding.json"
		dstEmbeddingFile := dstSupplierPath + "/embedding.json"
		if !public.FileExists(dstEmbeddingFile) {
			fBody, err := os.ReadFile(srcEmbeddingFile)
			if err != nil {
				continue
			}
			os.WriteFile(dstEmbeddingFile, fBody, os.ModePerm)
		}
	}

	IsSyncTemplateToConfig = true

}

func Status() bool {
	return len(Models("")) > 0 // Ensure models are loaded to check their status
}

// List retrieves a list of suppliers from the configuration directory.
// It reads the supplier configuration files and returns a slice of Supplier structs.
func List() []Supplier {
	SyncTemplateToConfig() // Ensure templates are synced before listing suppliers

	if !public.FileExists(SUPPLIER_CONFIG_PATH) {
		return nil
	}

	supplierList := make([]Supplier, 0)
	supplierNameList, err := os.ReadDir(SUPPLIER_CONFIG_PATH) // This is just a placeholder for the actual implementation
	if err != nil {
		return supplierList
	}
	for _, supplier := range supplierNameList {
		if !supplier.IsDir() {
			continue
		}

		if supplier.Name() == "template" {
			continue
		}

		supplierPath := SUPPLIER_CONFIG_PATH + "/" + supplier.Name()
		configFile := supplierPath + "/config.json"
		if !public.FileExists(configFile) {
			continue
		}

		fBody, err := os.ReadFile(configFile)
		if err != nil {
			continue
		}
		var supplierConfig Supplier
		err = json.Unmarshal(fBody, &supplierConfig)
		if err != nil {
			continue
		}

		if supplierConfig.BaseUrl == "" || supplierConfig.ApiKey == "" {
			supplierConfig.Status = false // If base URL or API key is missing, set status to false
		}

		supplierList = append(supplierList, supplierConfig)
	}

	// Sort suppliers by their sort order ASC
	if len(supplierList) > 0 {
		sort.Slice(supplierList, func(i, j int) bool {
			return supplierList[i].Sort < supplierList[j].Sort
		})
	}

	return supplierList
}

// Models retrieves the list of models for a given supplier from the models.json file.
// It reads the file, unmarshals the JSON content into a slice of ModelInfo structs, and returns it.
// If the file does not exist or an error occurs, it returns an empty slice.
func GetModelList(supplierName string) []ModelInfo {
	modelsFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/models.json"

	Models := make([]ModelInfo, 0)
	if !public.FileExists(modelsFile) {
		return Models
	}

	supplierConfig, err := ReadSupplierConfig(supplierName)
	if err != nil {
		return Models
	}

	isActive := supplierConfig.Status && supplierConfig.ApiKey != "" && supplierConfig.BaseUrl != ""
	// if supplierConfig.Status == false || supplierConfig.ApiKey == "" || supplierConfig.BaseUrl == "" {
	// 	return Models // If the supplier is not active or missing API key/base URL, return empty models
	// }

	fBody, err := os.ReadFile(modelsFile)
	if err != nil {
		return Models
	}

	err = json.Unmarshal(fBody, &Models)
	if err != nil {
		return Models
	}

	for i := 0; i < len(Models); i++ {
		if Models[i].Title == "" {
			Models[i].Title = fmt.Sprintf("%s/%s", supplierName, Models[i].ModelId)
		}
		if Models[i].MaxTokens == 0 {
			Models[i].MaxTokens = 8192 // Default max tokens if not specified
		}

		if !isActive {
			Models[i].Status = false
		}
	}

	return Models
}

// GetModelInfo retrieves a specific model's information by its ID from the supplier's model list.
// It iterates through the models and returns the one that matches the provided modelId.
func GetModelInfo(supplierName string, modelId string) *ModelInfo {
	models := GetModelList(supplierName)
	for _, model := range models {
		if model.ModelId == modelId {
			return &model
		}
	}
	return nil
}

// saveModelsToFile saves the provided models to the specified file in JSON format.
// It marshals the models slice into JSON with indentation for readability.
func saveModelsToFile(modelsFile string, models []ModelInfo) error {
	fBody, err := json.MarshalIndent(models, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(modelsFile, fBody, os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}

// SaveModelInfo saves or updates a model's information in the supplier's models.json file.
// If the model already exists, it updates the existing entry; otherwise, it appends the new model.
// It reads the existing models, modifies or adds the new model, and writes the updated list.
func SaveModelInfo(supplierName string, modelId string, modelInfo ModelInfo) error {
	modelsFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/models.json"

	// Read existing models
	existingModels := GetModelList(supplierName)

	// Update or add the model
	for i, model := range existingModels {
		if model.ModelId == modelId {
			existingModels[i] = modelInfo
			return saveModelsToFile(modelsFile, existingModels)
		}
	}

	// If not found, append the new model
	existingModels = append(existingModels, modelInfo)
	return saveModelsToFile(modelsFile, existingModels)
}

// GetCloudModels fetches the list of models from the supplier's API and saves them to the models.json file.
// It constructs the API URL using the supplier's base URL and sends a GET request with the API key.
// It processes the response to extract model information and saves it in the models.json file.
func GetCloudModels(supplierName string) {
	supplierConfig, err := ReadSupplierConfig(supplierName)
	if err != nil {
		return
	}
	if supplierConfig.ApiKey == "" || supplierConfig.BaseUrl == "" {
		return
	}

	apiUrl := supplierConfig.BaseUrl + "/models"
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+supplierConfig.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return // Handle error appropriately, e.g., log it or return an error
	}

	var response struct {
		Data []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}

	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if err := json.Unmarshal(resultBody, &response); err != nil {
		return
	}

	// Process the response data
	for _, model := range response.Data {
		// Map the API response to the ModelInfo struct
		modelInfo := ModelInfo{
			Title:        "",
			SupplierName: supplierName,
			ModelId:      model.ID,
			MaxTokens:    8192,
			Capability:   []string{"llm"}, // Default capability, can be updated later
			Status:       true,
		}
		// Save or update the model information
		SaveModelInfo(supplierName, model.ID, modelInfo)
	}
}

// Models retrieves a list of models for a specific supplier or all suppliers if no name is provided.
// It checks the status of each model and returns only those that are active if no supplier name is specified.
func Models(supplierName string) []ModelInfo {
	supplierList := make([]string, 0)
	if supplierName != "" {
		supplierList = append(supplierList, supplierName)
	} else {
		// If no supplier name is provided, list all suppliers
		supplierDirList, err := os.ReadDir(SUPPLIER_CONFIG_PATH)
		if err != nil {
			return nil
		}
		for _, supplier := range supplierDirList {
			if !supplier.IsDir() || supplier.Name() == "template" {
				continue
			}
			supplierList = append(supplierList, supplier.Name())
		}
	}
	// Filter models by status
	isCheckStatus := false
	if supplierName == "" {
		isCheckStatus = true
	}

	models := make([]ModelInfo, 0)
	for _, supplier := range supplierList {
		supplierModels := GetModelList(supplier)
		if len(supplierModels) == 0 && isCheckStatus == false {
			// 自动从供应商API获取模型列表
			GetCloudModels(supplier)
			supplierModels = GetModelList(supplier) // Re-fetch after getting cloud models
		}
		models = append(models, supplierModels...)
	}

	if isCheckStatus {
		modelList := make([]ModelInfo, 0)
		for i := 0; i < len(models); i++ {
			if models[i].Status {
				modelList = append(modelList, models[i])
			}
		}
		return modelList
	}

	return models
}

// AddModel adds a new model to the specified supplier's models.json file.
// It creates a ModelInfo struct with the provided details and saves it using SaveModelInfo.
// If the model already exists, it updates the existing entry with the new information.
func AddModel(supplierName string, title string, modelId string, max_tokens int, capability []string) error {
	modelInfo := ModelInfo{
		Title:        title,
		SupplierName: supplierName,
		ModelId:      modelId,
		MaxTokens:    max_tokens,
		Capability:   capability,
		Status:       true,
	}

	return SaveModelInfo(supplierName, modelId, modelInfo)
}

// RemoveModel removes a model from the specified supplier's models.json file.
// It reads the existing models, finds the model with the specified modelId, and removes it.
// If the model is found and removed, it saves the updated list back to the file.
func RemoveModel(supplierName string, modelId string) error {
	modelsFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/models.json"

	// Read existing models
	existingModels := GetModelList(supplierName)

	// Remove the model
	for i, model := range existingModels {
		if model.ModelId == modelId {
			existingModels = append(existingModels[:i], existingModels[i+1:]...)
			return saveModelsToFile(modelsFile, existingModels)
		}
	}

	return nil // Model not found, nothing to remove
}

// SaveSupplierConfig saves the supplier configuration to a JSON file.
// It creates the necessary directory structure if it doesn't exist and writes the configuration to config.json.
func SaveSupplierConfig(supplierName string, supplierConfig Supplier) error {
	configDir := SUPPLIER_CONFIG_PATH + "/" + supplierName
	if !public.FileExists(configDir) {
		err := os.MkdirAll(configDir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	configFile := configDir + "/config.json"

	fBody, err := json.MarshalIndent(supplierConfig, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(configFile, fBody, os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}

// ReadSupplierConfig reads the supplier configuration from a JSON file.
// It checks if the configuration file exists, reads its content, and unmarshals it into a Supplier struct.
func ReadSupplierConfig(supplierName string) (*Supplier, error) {
	configFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/config.json"
	if !public.FileExists(configFile) {
		return nil, os.ErrNotExist
	}
	fBody, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var supplierConfig Supplier
	err = json.Unmarshal(fBody, &supplierConfig)
	if err != nil {
		return nil, err
	}
	return &supplierConfig, nil
}

// SetSupplierConfig updates the supplier configuration with the provided base URL and API key.
// It reads the existing configuration, modifies it, and saves it back to the file.
// If the configuration file does not exist, it returns an error indicating that the supplier configuration was not found.
// This function is useful for updating the supplier's API settings without needing to recreate the entire configuration.
func SetSupplierConfig(supplierName string, baseUrl string, apiKey string) error {
	supplierConfig, err := ReadSupplierConfig(supplierName)
	if err != nil {
		return errors.New("supplier configuration not found")
	}

	supplierConfig.BaseUrl = baseUrl
	supplierConfig.ApiKey = apiKey

	return SaveSupplierConfig(supplierName, *supplierConfig)
}

// Testing validates the supplier's configuration by checking the base URL and API key.
// It performs the following checks:
// 1. Validates the base URL format.
// 2. Tests the accessibility of the base URL by sending a HEAD request.
// 3. Validates the API key by sending a GET request to the models endpoint.
// If any of these checks fail, it returns an error indicating the issue.
func Testing(supplierName, baseUrl, apiKey string) error {
	if supplierName == "" || baseUrl == "" || apiKey == "" {
		return errors.New("supplier name, base URL, and API key are required")
	}

	// Validate base URL format
	parsedUrl, err := url.ParseRequestURI(baseUrl)
	if err != nil {
		return fmt.Errorf("invalid base URL format: %w", err)
	}
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return errors.New("base URL must use http or https protocol")
	}
	// Ensure the base URL ends with a slash
	if err := testBaseURLAccessibility(baseUrl); err != nil {
		return fmt.Errorf("base URL accessibility test failed: %w", err)
	}
	// Validate API key by making a request to the models endpoint
	if err := testAPIKeyValidity(baseUrl, apiKey); err != nil {
		return fmt.Errorf("API key validation failed: %w", err)
	}

	return nil
}

// testBaseURLAccessibility checks if the base URL is accessible by sending a HEAD request.
// It returns an error if the request fails or if the response status is not OK (200).
func testBaseURLAccessibility(baseUrl string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Head(baseUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// testAPIKeyValidity checks if the provided API key is valid by making a GET request to the models endpoint.
// It constructs the API URL using the base URL and sends a request with the API key in the Authorization header.
// It returns an error if the request fails, if the response status is unauthorized (401),
// or if the response status is not OK (200) or not found (404).
func testAPIKeyValidity(baseUrl, apiKey string) error {
	apiUrl := baseUrl + "/models"
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil // API key is successfully validated
	case http.StatusUnauthorized:
		return errors.New("invalid API key")
	case http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("unexpected API response: %d %s",
			resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

// GetSupplierConfig retrieves the configuration for a specific supplier by its name.
// It reads the configuration file and returns a Supplier struct containing the supplier's details.
// If the configuration file does not exist or an error occurs, it returns an error.
func GetSupplierConfig(supplierName string) (*Supplier, error) {
	return ReadSupplierConfig(supplierName)
}

// SetSupplierStatus updates the status of a supplier in its configuration file.
// It reads the existing configuration, modifies the status, and saves it back to the file.
func SetSupplierStatus(supplierName string, status bool) error {
	supplierConfig, err := ReadSupplierConfig(supplierName)
	if err != nil {
		return errors.New("supplier configuration not found")
	}
	if supplierConfig.ApiKey == "" || supplierConfig.BaseUrl == "" {
		return errors.New("supplier configuration is incomplete, cannot set status")
	}
	supplierConfig.Status = status

	return SaveSupplierConfig(supplierName, *supplierConfig)
}

// SetModelStatus updates the status of a specific model in the supplier's models.json file.
// It reads the existing models, modifies the status of the specified model, and saves the updated list back to the file.
// If the model is not found, it returns an error indicating that the model does not exist
func SetModelStatus(supplierName string, modelId string, status bool) error {
	modelsFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/models.json"

	// Read existing models
	existingModels := GetModelList(supplierName)

	// Update the model status
	for i, model := range existingModels {
		if model.ModelId == modelId {
			existingModels[i].Status = status
			return saveModelsToFile(modelsFile, existingModels)
		}
	}

	return errors.New("model not found")
}

// AddSupplier creates a new supplier configuration file with the provided details.
// It checks if a supplier with the same name already exists, and if not, it creates a new Supplier struct
func AddSupplier(supplierTitle string, supplierName string, baseUrl string, apiKey string) error {
	supplierPath := SUPPLIER_CONFIG_PATH + "/" + supplierName
	if public.FileExists(supplierPath) {
		return errors.New("supplier already exists")
	}

	supplier := Supplier{
		SupplierTitle:   supplierTitle,
		SupplierName:    supplierName,
		BaseUrl:         baseUrl,
		BaseUrlExample:  baseUrl,
		IsUseUrlExample: false,
		ApiKey:          apiKey,
		Home:            "",
		Help:            "",
		Status:          true,
		Sort:            100, // Default sort order, can be changed later
		Icon:            "",  // Default icon, can be set later
	}

	return SaveSupplierConfig(supplierName, supplier)
}

// RemoveSupplier deletes a supplier's configuration directory and all its contents.
// It checks if the supplier exists, and if so, it removes the directory and its files
// If the supplier does not exist, it returns an error indicating that the supplier cannot be found.
// This function is useful for cleaning up unused suppliers from the configuration.
func RemoveSupplier(supplierName string) error {
	supplierPath := SUPPLIER_CONFIG_PATH + "/" + supplierName
	if !public.FileExists(supplierPath) {
		return errors.New("supplier does not exist")
	}
	templatePath := SUPPLIER_TEMPLATE_PATH + "/" + supplierName
	if public.FileExists(templatePath) {
		return errors.New("Cannot delete the system's built-in model supplier.")
	}

	err := os.RemoveAll(supplierPath)
	if err != nil {
		return err
	}

	return nil
}

// SetModelTitle updates the title of a model in the supplier's models.json file.
// It reads the existing models, modifies the title of the specified model, and saves the updated list back to the file.
// If the model is not found, it returns an error indicating that the model does not exist.
func SetModelTitle(supplierName string, modelId string, title string) error {
	modelsFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/models.json"
	if !public.FileExists(modelsFile) {
		return errors.New("models file does not exist for supplier: " + supplierName)
	}

	// Read existing models
	existingModels := GetModelList(supplierName)

	// Update the model title
	for i, model := range existingModels {
		if model.ModelId == modelId {
			existingModels[i].Title = title
			return saveModelsToFile(modelsFile, existingModels)
		}
	}

	return errors.New("model not found")
}

// SetModelCapability updates the capability of a specific model in the supplier's models.json file.
// It reads the existing models, modifies the capability of the specified model, and saves the updated list back to the file.
// If the model is not found, it returns an error indicating that the model does not exist.
func SetModelCapability(supplierName string, modelId string, capability []string) error {
	modelsFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/models.json"
	if !public.FileExists(modelsFile) {
		return errors.New("models file does not exist for supplier: " + supplierName)
	}

	// Read existing models
	existingModels := GetModelList(supplierName)

	// Update the model capability
	for i, model := range existingModels {
		if model.ModelId == modelId {
			existingModels[i].Capability = capability
			return saveModelsToFile(modelsFile, existingModels)
		}
	}

	return errors.New("model not found")
}

// ModifyModel updates the title, maxTokens, and capability of a specific model in the supplier's models.json file.
// It reads the existing models, modifies the specified model's details, and saves the updated list back to the file.
// If the model is not found, it returns an error indicating that the model does not exist.
// This function is useful for updating model configurations without needing to remove and re-add the model.
func ModifyModel(supplierName string, modelId string, maxTokens int, capability []string, title string) error {
	modelsFile := SUPPLIER_CONFIG_PATH + "/" + supplierName + "/models.json"
	if !public.FileExists(modelsFile) {
		return errors.New("models file does not exist for supplier: " + supplierName)
	}
	// Read existing models
	existingModels := GetModelList(supplierName)

	// Update or add the model
	for i, model := range existingModels {
		if model.ModelId == modelId {
			existingModels[i].Title = title
			existingModels[i].MaxTokens = maxTokens
			existingModels[i].Capability = capability
			return saveModelsToFile(modelsFile, existingModels)
		}
	}

	return errors.New("model not found")
}
