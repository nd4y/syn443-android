package bridge

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// Preserve exact key presence before a typed decoder could discard duplicates,
// case substitutions or null/empty predicates intended for a different method.
func (c *routeCheck) UnmarshalJSON(raw []byte) error {
	if len(raw) < 2 || len(raw) > 4096 || !utf8.Valid(raw) {
		return errPrivatePath
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errPrivatePath
	}
	seen := map[string]bool{}
	var result routeCheck
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || len(seen) == 4 {
			return errPrivatePath
		}
		seen[key] = true
		token, err = d.Token()
		if err != nil {
			return errPrivatePath
		}
		if key == "expected_status" {
			value, ok := token.(json.Number)
			if !ok {
				return errPrivatePath
			}
			code, err := value.Int64()
			if err != nil || code < 200 || code > 599 {
				return errPrivatePath
			}
			result.ExpectedStatus = int(code)
			continue
		}
		value, ok := token.(string)
		if !ok {
			return errPrivatePath
		}
		switch key {
		case "method":
			result.Method = value
		case "target":
			result.Target = value
		case "expected_ip":
			result.ExpectedIP = value
		case "expected_exit_class":
			result.ExpectedExitClass = value
		case "http_method":
			result.HTTPMethod = value
		default:
			return errPrivatePath
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return errPrivatePath
	}
	if _, err = d.Token(); err != io.EOF || !seen["method"] || !seen["target"] ||
		seen["expected_ip"] != (result.Method == "https_exit_ip") ||
		seen["http_method"] != (result.Method == "https_status") || seen["expected_status"] != (result.Method == "https_status") ||
		seen["expected_exit_class"] != (result.Method == "https_exit_country") || !validRouteCheck(result) {
		return errPrivatePath
	}
	*c = result
	return nil
}
