package app

import "testing"

func TestVirtualMatchStringFromPURL(t *testing.T) {
	vms, err := VirtualMatchStringFromPURL("pkg:npm/express@4.18.0")
	if err != nil {
		t.Fatal(err)
	}
	want := "cpe:2.3:a:*:express:4.18.0:*:*:*:*:*:*:*"
	if vms != want {
		t.Fatalf("got %q want %q", vms, want)
	}

	vms2, err := VirtualMatchStringFromPURL("pkg:npm/@types/node@18.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if vms2 != "cpe:2.3:a:*:types\\/node:18.0.0:*:*:*:*:*:*:*" {
		t.Fatalf("scoped npm: got %q", vms2)
	}
}

func TestVirtualMatchStringFromPURL_errors(t *testing.T) {
	_, err := VirtualMatchStringFromPURL("pkg:npm/foo")
	if err == nil {
		t.Fatal("expected error without version")
	}
}
