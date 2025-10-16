// core/internal/controller/contact/contact_v1_export_contacts.go
package contact

import (
	"archive/zip"
	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
	"strings"
	"time"
)

func (c *ControllerV1) ExportContacts(ctx context.Context, req *v1.ExportContactsReq) (res *v1.ExportContactsRes, err error) {
	res = &v1.ExportContactsRes{}

	// Set default value for including inactive contacts
	if req.IncludeInactive == false {
		// Default to true if not explicitly set in request
		req.IncludeInactive = true
	}

	// Get request object
	r := g.RequestFromCtx(ctx)
	if r == nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Unable to obtain the request context")))
		return
	}

	if req.ExportType == 1 { // Merged export
		// Use map to handle duplicate contact status
		contactMap := make(map[string]*entity.Contact)

		// Get contacts from all groups
		for _, groupId := range req.GroupIds {
			contacts, err := contact.GetContactsByGroup(ctx, groupId)
			if err != nil {
				continue
			}
			// Filter contacts based on IncludeInactive
			for _, c := range contacts {
				if existing, ok := contactMap[c.Email]; ok {
					// If there is a status conflict (one subscribed, one unsubscribed), use the unsubscribed status
					if existing.Active != c.Active {
						existing.Active = 0
					}
					// If the status is the same, keep the original status
				} else {
					contactMap[c.Email] = c
				}
			}
		}

		// Convert to slice and apply IncludeInactive filter
		var allContacts []*entity.Contact
		for _, c := range contactMap {
			if c.Active == 1 || req.IncludeInactive {
				allContacts = append(allContacts, c)
			}
		}

		// Export file based on format
		var content string
		var fileName string
		timestamp := gtime.Now().Format("YmdHis")

		switch req.Format {
		case "csv":
			content, err = exportContactsToCSV(allContacts)
			fileName = fmt.Sprintf("contacts_export_%s.csv", timestamp)
		case "txt":
			content, err = exportContactsToTXT(allContacts)
			fileName = fmt.Sprintf("contacts_export_%s.txt", timestamp)
		case "excel":
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Excel format not implemented")))
			return
		default:
			res.Code = 400
			res.SetError(gerror.New(public.LangCtx(ctx, "Unsupported format")))
			return
		}

		if err != nil {
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to export contacts")))
			return
		}

		// Set response headers for file download
		r.Response.Header().Set("Content-Type", "application/octet-stream")
		r.Response.Header().Set("Content-Disposition", "attachment; filename="+fileName)
		r.Response.Write([]byte(content))

	} else { // Separate export - ZIP file
		var files []ExportFile

		// Create file for each group
		for _, groupId := range req.GroupIds {
			group, err := contact.GetGroup(ctx, groupId)
			if err != nil {
				continue
			}

			contacts, err := contact.GetContactsByGroup(ctx, groupId)
			if err != nil {
				continue
			}

			// Filter contacts based on IncludeInactive
			var filteredContacts []*entity.Contact
			for _, c := range contacts {
				if c.Active == 1 || req.IncludeInactive {
					filteredContacts = append(filteredContacts, c)
				}
			}

			if len(filteredContacts) == 0 {
				continue
			}

			// Export file content
			var content string
			switch req.Format {
			case "csv":
				content, err = exportContactsToCSV(filteredContacts)
			case "txt":
				content, err = exportContactsToTXT(filteredContacts)
			case "excel":
				res.Code = 500
				res.SetError(gerror.New(public.LangCtx(ctx, "Excel format not implemented")))
				return nil, nil
			default:
				res.Code = 400
				res.SetError(gerror.New(public.LangCtx(ctx, "Unsupported format")))
				return nil, nil
			}

			if err != nil {
				continue
			}

			fileName := fmt.Sprintf("%s.%s", group.Name, req.Format)
			files = append(files, ExportFile{
				Name:     fileName,
				Content:  content,
				Contacts: len(filteredContacts),
			})
		}

		if len(files) == 0 {
			res.Code = 400
			res.SetError(gerror.New(public.LangCtx(ctx, "No contacts to export")))
			return nil, nil
		}

		// Create ZIP file in memory
		timestamp := gtime.Now().Format("YmdHis")
		zipFileName := fmt.Sprintf("contacts_export_%s.zip", timestamp)

		zipContent, err := createZipFileInMemory(files)
		if err != nil {
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to create zip file")))
			return nil, nil
		}

		// Set response headers for ZIP file download
		r.Response.Header().Set("Content-Type", "application/octet-stream")
		r.Response.Header().Set("Content-Disposition", "attachment; filename="+zipFileName)
		r.Response.Write(zipContent)
	}

	var groups []*entity.ContactGroup
	err = g.DB().Model("bm_contact_groups").Ctx(ctx).WhereIn("id", req.GroupIds).Scan(&groups)
	groupNames := make([]string, 0, len(groups))
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}
	groupNamesStr := strings.Join(groupNames, ", ")

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.ContactsGroup,
		Log:  fmt.Sprintf("Contacts Group exported successfully: %s ", groupNamesStr),
	})

	res.SetSuccess(public.LangCtx(ctx, "Contacts exported successfully"))
	return res, nil
}

// ExportFile Export file information
type ExportFile struct {
	Name     string // File name
	Content  string // File content
	Contacts int    // Contact count
}

// createZipFileInMemory creates a ZIP file in memory
func createZipFileInMemory(files []ExportFile) ([]byte, error) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	for _, file := range files {
		// Create zip entry
		zipEntry, err := zipWriter.Create(file.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to create zip entry for %s: %v", file.Name, err)
		}

		// Write file content to zip
		_, err = zipEntry.Write([]byte(file.Content))
		if err != nil {
			return nil, fmt.Errorf("failed to write content to zip for %s: %v", file.Name, err)
		}
	}

	err := zipWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close zip writer: %v", err)
	}

	return buf.Bytes(), nil
}

// exportContactsToCSV exports contacts to CSV format
func exportContactsToCSV(contacts []*entity.Contact) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write CSV headers
	headers := []string{
		"email",       // Email address
		"attributes",  // Attributes
		"active",      // Active status
		"create_time", // Create time
	}
	if err := writer.Write(headers); err != nil {
		return "", err
	}

	// Write data rows
	for _, c := range contacts {
		if c.Attribs == nil {
			c.Attribs = make(map[string]string)
		}
		// Convert attributes to JSON string
		attribsJSON, err := json.Marshal(c.Attribs)
		if err != nil {
			attribsJSON = []byte("{}")
		}

		// Format time
		createdAt := ""
		if c.CreateTime != 0 {
			// Convert timestamp to time string
			t := time.Unix(int64(c.CreateTime), 0)
			createdAt = t.Format("2006-01-02 15:04:05")
		}

		row := []string{
			c.Email,
			string(attribsJSON),
			fmt.Sprintf("%d", c.Active),
			createdAt,
		}
		if err := writer.Write(row); err != nil {
			return "", err
		}
	}

	writer.Flush()
	return buf.String(), nil
}

// exportContactsToTXT exports contacts to TXT format
func exportContactsToTXT(contacts []*entity.Contact) (string, error) {
	var lines []string
	for _, c := range contacts {
		// Convert attributes to JSON string
		attribsJSON, err := json.Marshal(c.Attribs)
		if err != nil {
			attribsJSON = []byte("{}")
		}

		// Format create time
		createdAt := ""
		if c.CreateTime != 0 {
			// Convert timestamp to time string
			t := time.Unix(int64(c.CreateTime), 0)
			createdAt = t.Format("2006-01-02 15:04:05")
		}

		// Format: email,attributes,active,created_at
		line := fmt.Sprintf("%s,%s,%d,%s",
			c.Email,
			string(attribsJSON),
			c.Active,
			createdAt,
		)
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"), nil
}
