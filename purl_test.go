package main

import (
	"testing"
)

func TestParsePURL(t *testing.T) {
	tests := []struct {
		raw              string
		wantType         string
		wantNamespace    string
		wantName         string
		wantVersion      string
		wantErr          bool
		wantProductForCPE string
	}{
		{
			raw:              "pkg:npm/express@4.18.0",
			wantType:         "npm",
			wantNamespace:    "",
			wantName:         "express",
			wantVersion:      "4.18.0",
			wantProductForCPE: "express",
		},
		{
			raw:              "pkg:npm/@scope/pkg@1.0.0",
			wantType:         "npm",
			wantNamespace:    "@scope",
			wantName:         "pkg",
			wantVersion:      "1.0.0",
			wantProductForCPE: "scope/pkg",
		},
		{
			raw:              "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			wantType:         "maven",
			wantNamespace:    "org.apache.commons",
			wantName:         "commons-lang3",
			wantVersion:      "3.12.0",
			wantProductForCPE: "org.apache.commons/commons-lang3",
		},
		{
			raw:         "not-a-purl",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			p, err := ParsePURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Type != tt.wantType || p.Namespace != tt.wantNamespace || p.Name != tt.wantName || p.Version != tt.wantVersion {
				t.Fatalf("got %+v want type=%q ns=%q name=%q ver=%q", p, tt.wantType, tt.wantNamespace, tt.wantName, tt.wantVersion)
			}
			if tt.wantProductForCPE != "" && p.ProductNameForCPE() != tt.wantProductForCPE {
				t.Fatalf("ProductNameForCPE()=%q want %q", p.ProductNameForCPE(), tt.wantProductForCPE)
			}
		})
	}
}
