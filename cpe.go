package main

import (
	"fmt"
	"strings"
)

// cpeSpecialChars must be backslash-escaped in CPE 2.3 name form (URI binding).
// See NIST IR 7695 — order matters: escape backslashes first.
var cpeSpecial = []string{
	`\`, `\\`,
	`!`, `\!`,
	`"`, `\"`,
	`#`, `\#`,
	`$`, `\$`,
	`%`, `\%`,
	`&`, `\&`,
	`'`, `\'`,
	`(`, `\(`,
	`)`, `\)`,
	`*`, `\*`,
	`+`, `\+`,
	`,`, `\,`,
	`/`, `\/`,
	`:`, `\:`,
	`;`, `\;`,
	`<`, `\<`,
	`=`, `\=`,
	`>`, `\>`,
	`?`, `\?`,
	`@`, `\@`,
	`[`, `\[`,
	`]`, `\]`,
	`^`, `\^`,
	"\u0060", "\\`",
	`{`, `\{`,
	`|`, `\|`,
	`}`, `\}`,
	`~`, `\~`,
}

func cpeEscapeComponent(s string) string {
	out := s
	for i := 0; i < len(cpeSpecial); i += 2 {
		out = strings.ReplaceAll(out, cpeSpecial[i], cpeSpecial[i+1])
	}
	return out
}

// VirtualMatchStringFromPURL builds a CPE match string for NVD's virtualMatchString
// parameter. NVD cpeName rejects wildcard vendor/product; virtualMatchString allows
// matching broader CPE criteria (e.g. vendor *).
//
// Form: cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*
func VirtualMatchStringFromPURL(purl string) (string, error) {
	parsed, err := ParsePURL(purl)
	if err != nil {
		return "", err
	}
	prod := strings.TrimSpace(parsed.ProductNameForCPE())
	ver := strings.TrimSpace(parsed.Version)
	if prod == "" {
		return "", fmt.Errorf("purl has no product name")
	}
	if ver == "" {
		return "", fmt.Errorf("purl has no version (required for CPE match)")
	}
	prod = cpeEscapeComponent(prod)
	ver = cpeEscapeComponent(ver)
	// part : vendor : product : version : update : edition : language : sw_edition : target_sw : target_hw : other
	return fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", prod, ver), nil
}
