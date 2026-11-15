package bridge

import (
	"encoding/json"
	"testing"
)

func TestRouteCheckWireCannotDiscardDuplicateCaseOrForeignPredicates(t *testing.T) {
	for _, raw := range []string{
		`{"method":"tcp","target":"example.invalid:443"}`,
		`{"method":"https_exit_ip","target":"https://example.invalid/ip","expected_ip":"192.0.2.9"}`,
		`{"method":"https_exit_country","target":"https://example.invalid/","expected_exit_class":"RU"}`,
		`{"expected_exit_class":"NON_RU","target":"https://example.invalid","method":"https_exit_country"}`,
	} {
		var check routeCheck
		if json.Unmarshal([]byte(raw), &check) != nil || !validRouteCheck(check) {
			t.Fatal("valid exact check lost")
		}
		encoded, err := json.Marshal(check)
		var again routeCheck
		if err != nil || json.Unmarshal(encoded, &again) != nil || again != check {
			t.Fatal("check did not round-trip")
		}
	}
	for _, raw := range []string{
		`{"method":"tcp","target":"example.invalid:443","expected_exit_class":""}`,
		`{"method":"tcp","target":"example.invalid:443","expected_ip":null}`,
		`{"method":"https_exit_country","target":"https://example.invalid/","expected_exit_class":"RU","expected_ip":""}`,
		`{"method":"https_exit_country","target":"https://example.invalid/"}`,
		`{"method":"https_exit_country","target":"https://example.invalid/","expected_exit_class":null}`,
		`{"method":"https_exit_country","target":"https://example.invalid/","expected_exit_class":"RU","expected_exit_class":"NON_RU"}`,
		`{"method":"tcp","Method":"tls","target":"example.invalid:443"}`,
		`{"method":"tcp","method":"tcp","target":"example.invalid:443"}`,
		`{"method":"tcp","m\u0065thod":"tcp","target":"example.invalid:443"}`,
		`{"method":"tcp","target":12}`,
		`{"method":"tcp","target":{"target":"example.invalid:443"}}`,
		`null`, `[]`, `{"method":"tcp","target":"example.invalid:443"} true`,
	} {
		before := routeCheck{Method: "tls", Target: "https://example.invalid/"}
		check := before
		if json.Unmarshal([]byte(raw), &check) == nil || check != before {
			t.Fatal("invalid check accepted or mutated receiver")
		}
	}
}
