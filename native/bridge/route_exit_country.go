package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/language"
)

const exitCountryBodyLimit = 512
const exitCountryHeaderLimit = 8192
const exitCountryFramedBodyLimit = 2048

// Current ISO 3166-1 alpha-2 assignments. CLDR IsCountry also accepts historical
// and non-ISO regions; those cannot prove a public RU/NON_RU exit classification.
const exitCountryISO = " AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW "

func validExitCountryTarget(c routeCheck) bool {
	if c.ExpectedExitClass != "RU" && c.ExpectedExitClass != "NON_RU" || c.ExpectedIP != "" ||
		strings.IndexFunc(c.Target, func(r rune) bool { return r <= 32 || r > 126 }) >= 0 {
		return false
	}
	u, err := url.Parse(c.Target)
	return err == nil && u.Scheme == "https" && u.Opaque == "" && u.Hostname() != "" && u.User == nil &&
		!strings.ContainsAny(c.Target, "#\\") && !strings.HasSuffix(u.Host, ":") &&
		(u.Port() == "" || validRoutePort(u.Port())) && (u.Path == "" || u.Path == "/") &&
		u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery
}

func validExitCountry(raw string) bool {
	if len(raw) != 2 || raw[0] < 'A' || raw[0] > 'Z' || raw[1] < 'A' || raw[1] > 'Z' ||
		!strings.Contains(exitCountryISO, " "+raw+" ") {
		return false
	}
	region, err := language.ParseRegion(raw)
	return err == nil && region.String() == raw && region.IsCountry() && !region.IsPrivateUse() && region.ISO3() != "ZZZ"
}

// Parse exact, case-sensitive keys without encoding/json's duplicate-key,
// case-folding, null-to-zero or invalid-UTF8 substitution behavior. The checked
// service's response is evidence for this candidate and sample only, not a
// promise about all later egress or precise physical geography.
func exitCountryClass(body []byte) (string, bool) {
	if len(body) == 0 || len(body) > exitCountryBodyLimit || !utf8.Valid(body) {
		return "", false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	open, err := d.Token()
	if err != nil || open != json.Delim('{') {
		return "", false
	}
	seen := make(map[string]bool, 2)
	values := make(map[string]string, 2)
	for d.More() {
		keyToken, keyErr := d.Token()
		key, ok := keyToken.(string)
		if keyErr != nil || !ok || key != "ip" && key != "country" || seen[key] {
			return "", false
		}
		valueToken, valueErr := d.Token()
		value, ok := valueToken.(string)
		if valueErr != nil || !ok {
			return "", false
		}
		seen[key], values[key] = true, value
	}
	close, err := d.Token()
	if err != nil || close != json.Delim('}') || len(seen) != 2 {
		return "", false
	}
	if _, err = d.Token(); err != io.EOF {
		return "", false
	}
	if _, ok := routeExitIP(values["ip"]); !ok || !validExitCountry(values["country"]) {
		return "", false
	}
	if values["country"] == "RU" {
		return "RU", true
	}
	return "NON_RU", true
}

// Header reading is bounded before http.ReadResponse can allocate a whole
// attacker-controlled line. The same reader retains any prefetched body bytes;
// after the header, a separate wire budget also bounds chunk framing/trailers.
func readExitCountryResponse(conn io.Reader, req *http.Request) (*http.Response, error) {
	limited := &io.LimitedReader{R: conn, N: exitCountryHeaderLimit + 1}
	reader := bufio.NewReaderSize(limited, 1024)
	header := make([]byte, 0, 1024)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || len(header)+len(line) > exitCountryHeaderLimit {
			return nil, io.ErrUnexpectedEOF
		}
		header = append(header, line...)
		if line == "\r\n" {
			break
		}
	}
	// Account for unread header allowance rather than granting it a second time.
	buffered := reader.Buffered()
	limited.N = int64(exitCountryFramedBodyLimit - buffered)
	if limited.N < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return http.ReadResponse(bufio.NewReaderSize(io.MultiReader(bytes.NewReader(header), reader), 1024), req)
}

func probeExitCountryResponse(parent, ctx context.Context, conn io.Reader, req *http.Request, expected string) (string, bool) {
	response, err := readExitCountryResponse(conn, req)
	if parent.Err() != nil {
		return "cancelled", false
	}
	if ctx.Err() != nil {
		return "check_timeout", false
	}
	if err != nil {
		return "response_failed", true
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > exitCountryBodyLimit ||
		len(response.TransferEncoding) > 1 || len(response.TransferEncoding) == 1 && response.TransferEncoding[0] != "chunked" ||
		len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Age")) != 0 ||
		len(response.Trailer) != 0 {
		return "exit_evidence_invalid", true
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, exitCountryBodyLimit+1))
	if parent.Err() != nil {
		return "cancelled", false
	}
	if ctx.Err() != nil {
		return "check_timeout", false
	}
	actual, valid := exitCountryClass(body)
	if readErr != nil || !valid || len(response.Trailer) != 0 ||
		response.ContentLength >= 0 && int64(len(body)) != response.ContentLength {
		return "exit_evidence_invalid", true
	}
	if actual != expected {
		return "exit_country_mismatch", true
	}
	return "ok", true
}
