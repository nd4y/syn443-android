package bridge

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"testing"
)

type checkPlanSharedCase struct {
	Name       string            `json:"name"`
	Profile    json.RawMessage   `json:"profile"`
	SHA256     string            `json:"sha256"`
	Raw        string            `json:"raw"`
	Checks     []routeCheck      `json:"checks"`
	Results    map[string]string `json:"results"`
	Expected   string            `json:"expected"`
	Visited    []string          `json:"visited"`
	LeafStates map[string]string `json:"leafStates"`
}
type checkPlanSharedFile struct {
	SchemaVersion   int                   `json:"schemaVersion"`
	ValidCases      []checkPlanSharedCase `json:"validCases"`
	InvalidCases    []checkPlanSharedCase `json:"invalidCases"`
	InvalidRawCases []checkPlanSharedCase `json:"invalidRawCases"`
	TruthCases      []checkPlanSharedCase `json:"truthCases"`
	LegacyCases     []checkPlanSharedCase `json:"legacyCases"`
}

func readCheckPlanShared(t *testing.T) checkPlanSharedFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/route-check-profile-v2-vectors.json")
	if err != nil || len(raw) < 1 || len(raw) > 524288 {
		t.Fatal("missing bounded public check-plan vectors")
	}
	var result checkPlanSharedFile
	if json.Unmarshal(raw, &result) != nil || result.SchemaVersion != 1 {
		t.Fatal("malformed check-plan vectors")
	}
	for _, category := range []struct {
		values []checkPlanSharedCase
		count  int
	}{
		{result.ValidCases, 9}, {result.InvalidCases, 37}, {result.InvalidRawCases, 6}, {result.TruthCases, 51}, {result.LegacyCases, 1},
	} {
		if len(category.values) != category.count {
			t.Fatal("shared vector coverage drift")
		}
		seen := map[string]bool{}
		for _, item := range category.values {
			if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(item.Name) || seen[item.Name] {
				t.Fatal("duplicate or rewritten shared vector name")
			}
			seen[item.Name] = true
		}
	}
	return result
}

func TestCheckPlanV2ValidSharedVectors(t *testing.T) {
	for _, tc := range readCheckPlanShared(t).ValidCases {
		t.Run(tc.Name, func(t *testing.T) {
			var profile routeCheckProfile
			if json.Unmarshal(tc.Profile, &profile) != nil {
				t.Fatal("valid profile rejected")
			}
			program, err := newRouteCheckProgram(nil, &profile)
			if err != nil || program.hash != tc.SHA256 || program.count() != len(profile.Leaves) {
				t.Fatal("profile normalization/hash drift")
			}
			if program.String() != "RouteCheckProgram([redacted])" || profile.String() != "RouteCheckProfile([redacted])" {
				t.Fatal("profile details escaped formatting")
			}
		})
	}
}
func TestCheckPlanV2InvalidSharedVectors(t *testing.T) {
	for _, tc := range readCheckPlanShared(t).InvalidCases {
		t.Run(tc.Name, func(t *testing.T) {
			var profile routeCheckProfile
			if json.Unmarshal(tc.Profile, &profile) == nil {
				t.Fatal("invalid profile acquired a program")
			}
		})
	}
}
func TestCheckPlanV2InvalidRawSharedVectors(t *testing.T) {
	for _, tc := range readCheckPlanShared(t).InvalidRawCases {
		t.Run(tc.Name, func(t *testing.T) {
			var profile routeCheckProfile
			if json.Unmarshal([]byte(tc.Raw), &profile) == nil {
				t.Fatal("invalid raw profile acquired a program")
			}
		})
	}
}
func TestCheckPlanV2TruthSharedVectors(t *testing.T) {
	for _, tc := range readCheckPlanShared(t).TruthCases {
		t.Run(tc.Name, func(t *testing.T) {
			var profile routeCheckProfile
			if json.Unmarshal(tc.Profile, &profile) != nil {
				t.Fatal("invalid truth profile")
			}
			ids := map[routeCheck]string{}
			for _, leaf := range profile.Leaves {
				ids[leaf.Check] = leaf.ID
			}
			visited := []string{}
			result := evaluateRouteCheckProfile(context.Background(), &profile, func() int64 { return 1000 }, func() bool { return true },
				func(_ context.Context, check routeCheck) routeCheckProbeResult {
					id := ids[check]
					visited = append(visited, id)
					switch tc.Results[id] {
					case checkTrue:
						return routeCheckProbeResult{code: "ok", complete: true, witness: true}
					case checkFalse:
						return routeCheckProbeResult{code: "dial_failed", complete: true, witness: true}
					case checkUnknown:
						return routeCheckProbeResult{code: "probe_unavailable"}
					default:
						t.Fatal("missing truth observation")
						return routeCheckProbeResult{}
					}
				})
			if result.report.Outcome != tc.Expected || !reflect.DeepEqual(visited, tc.Visited) {
				t.Fatal("predicate/short-circuit drift", result.report.Outcome, visited)
			}
			states := map[string]string{}
			for _, leaf := range result.report.Leaves {
				states[leaf.ID] = leaf.Outcome
			}
			if !reflect.DeepEqual(states, tc.LeafStates) {
				t.Fatal("per-leaf uncertainty or skipped-state drift", states)
			}
			if tc.Expected == checkFalse && result.witness < 0 {
				t.Fatal("false predicate lost its admitted decisive witness")
			}
		})
	}
}
func TestCheckPlanV2LegacyHashSharedVectors(t *testing.T) {
	for _, tc := range readCheckPlanShared(t).LegacyCases {
		t.Run(tc.Name, func(t *testing.T) {
			program, err := newRouteCheckProgram(tc.Checks, nil)
			if err != nil || program.hash != tc.SHA256 || program.profile != nil {
				t.Fatal("legacy ordered-all hash changed")
			}
			plan := routePlan{ID: "r", Outbound: "proxy", Checks: tc.Checks}
			raw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			var decoded routePlan
			if json.Unmarshal(raw, &decoded) != nil || decoded.Profile != nil || !reflect.DeepEqual(decoded.Checks, tc.Checks) {
				t.Fatal("legacy route wire changed")
			}
		})
	}
}
