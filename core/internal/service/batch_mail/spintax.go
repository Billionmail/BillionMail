package batch_mail

import (
	"math/rand"
	"regexp"
	"strings"
	"time"
)

// SpintaxParser Spintax parser
type SpintaxParser struct {
	random *rand.Rand
}

// NewSpintaxParser Create a new Spintax parser
func NewSpintaxParser() *SpintaxParser {
	return &SpintaxParser{
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ParseSpintax Parse Spintax syntax with context awareness
// Supported format: {option1|option2|option3}
// Example: "Hello {{FirstName}}, I {want|thought|hope} to contact you..."
// Now avoids matching CSS/JS/HTML attribute contexts
func (p *SpintaxParser) ParseSpintax(content string) string {
	// Use context-aware parsing to avoid CSS/JS/HTML attribute interference
	return p.parseSpintaxWithContext(content, p.random)
}

// parseSpintaxWithContext parses Spintax with context awareness
func (p *SpintaxParser) parseSpintaxWithContext(content string, randGen *rand.Rand) string {
	if content == "" {
		return content
	}

	var result strings.Builder
	i := 0
	contentLen := len(content)

	for i < contentLen {
		// Check if we're entering a context where {} should be ignored
		if skipLen := p.getSkipLength(content, i); skipLen > 0 {
			// Copy the entire skipped section as-is
			result.WriteString(content[i : i+skipLen])
			i += skipLen
			continue
		}

		// Look for potential Spintax pattern
		if content[i] == '{' {
			if spintaxLen := p.parseSpintaxAtPosition(content, i, &result, randGen); spintaxLen > 0 {
				i += spintaxLen
				continue
			}
		}

		// Regular character, copy as-is
		result.WriteByte(content[i])
		i++
	}

	return result.String()
}

// getSkipLength returns the length of content to skip if we're in a CSS/JS/HTML attribute context
func (p *SpintaxParser) getSkipLength(content string, pos int) int {
	// Check for <style> tags
	if styleStart := p.findTagStart(content, pos, "style"); styleStart >= 0 {
		if styleEnd := strings.Index(content[pos:], "</style>"); styleEnd >= 0 {
			return styleEnd + 8 // include </style>
		}
	}

	// Check for <script> tags
	if scriptStart := p.findTagStart(content, pos, "script"); scriptStart >= 0 {
		if scriptEnd := strings.Index(content[pos:], "</script>"); scriptEnd >= 0 {
			return scriptEnd + 9 // include </script>
		}
	}

	// Check if we're inside an HTML tag (between < and >)
	if p.isInsideHtmlTag(content, pos) {
		return p.getHtmlTagEndOffset(content, pos)
	}

	return 0
}

// findTagStart checks if we're at the start of a specific HTML tag
func (p *SpintaxParser) findTagStart(content string, pos int, tagName string) int {
	if pos >= len(content) {
		return -1
	}

	// Look for <tagName or <tagName> or <tagName space
	pattern := "<" + tagName
	if strings.HasPrefix(strings.ToLower(content[pos:]), pattern) {
		nextCharPos := pos + len(pattern)
		if nextCharPos >= len(content) {
			return pos
		}
		nextChar := content[nextCharPos]
		if nextChar == '>' || nextChar == ' ' || nextChar == '\t' || nextChar == '\n' {
			return pos
		}
	}
	return -1
}

// isInsideHtmlTag checks if the position is inside an HTML tag
func (p *SpintaxParser) isInsideHtmlTag(content string, pos int) bool {
	// Look backward for the nearest < or >
	lastOpenTag := strings.LastIndex(content[:pos], "<")
	lastCloseTag := strings.LastIndex(content[:pos], ">")

	// If we found an open tag more recently than a close tag, we're inside a tag
	return lastOpenTag > lastCloseTag && lastOpenTag >= 0
}

// getHtmlTagEndOffset returns the offset to the end of the current HTML tag
func (p *SpintaxParser) getHtmlTagEndOffset(content string, pos int) int {
	if closeTagPos := strings.Index(content[pos:], ">"); closeTagPos >= 0 {
		return closeTagPos + 1
	}
	return len(content) - pos // rest of content if no closing >
}

// parseSpintaxAtPosition tries to parse Spintax at the given position
func (p *SpintaxParser) parseSpintaxAtPosition(content string, pos int, result *strings.Builder, randGen *rand.Rand) int {
	// Find the matching closing brace
	braceCount := 1
	i := pos + 1
	contentLen := len(content)

	for i < contentLen && braceCount > 0 {
		if content[i] == '{' {
			braceCount++
		} else if content[i] == '}' {
			braceCount--
		}
		i++
	}

	// If we didn't find a matching closing brace, it's not valid Spintax
	if braceCount != 0 {
		return 0
	}

	// Extract the content between braces
	innerContent := content[pos+1 : i-1]

	// Check if this looks like valid Spintax (contains | separator)
	if !strings.Contains(innerContent, "|") {
		return 0
	}

	// Validate that this is proper Spintax format
	options := strings.Split(innerContent, "|")
	validOptions := make([]string, 0, len(options))

	for _, option := range options {
		option = strings.TrimSpace(option)
		if option != "" {
			validOptions = append(validOptions, option)
		}
	}

	// If no valid options, treat as regular text
	if len(validOptions) == 0 {
		return 0
	}

	// Randomly select an option
	selectedIndex := randGen.Intn(len(validOptions))
	result.WriteString(validOptions[selectedIndex])

	return i - pos // return the length of parsed content
}

// ParseSpintaxWithSeed Parse Spintax with a specified seed (used for testing or reproducible results)
func (p *SpintaxParser) ParseSpintaxWithSeed(content string, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	// Use context-aware parsing with the specified seed
	return p.parseSpintaxWithContext(content, r)
}

// HasSpintax Check if the content contains Spintax syntax
func (p *SpintaxParser) HasSpintax(content string) bool {
	spintaxRegex := regexp.MustCompile(`\{([^}]+)\}`)
	return spintaxRegex.MatchString(content)
}

// GetSpintaxOptions Get all Spintax options (used for preview)
func (p *SpintaxParser) GetSpintaxOptions(content string) map[string][]string {
	spintaxRegex := regexp.MustCompile(`\{([^}]+)\}`)
	matches := spintaxRegex.FindAllStringSubmatch(content, -1)

	result := make(map[string][]string)
	for _, match := range matches {
		if len(match) >= 2 {
			original := match[0]
			optionsStr := match[1]

			options := strings.Split(optionsStr, "|")

			validOptions := make([]string, 0)
			for _, option := range options {
				option = strings.TrimSpace(option)
				if option != "" {
					validOptions = append(validOptions, option)
				}
			}

			result[original] = validOptions
		}
	}

	return result
}

// Global Spintax parser instance
var defaultSpintaxParser = NewSpintaxParser()

// GetSpintaxParser Get the default Spintax parser instance
func GetSpintaxParser() *SpintaxParser {
	return defaultSpintaxParser
}
