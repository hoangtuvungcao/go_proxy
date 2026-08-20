package geoip

import (
	"testing"
)

func TestGeoIPResolution(t *testing.T) {
	r := NewResolver(true)

	testCases := []struct {
		ip       string
		expected string
	}{
		{"14.225.207.61", "VN"},
		{"118.69.188.67", "VN"},
		{"116.104.85.226", "VN"},
		{"171.244.142.43", "VN"},
		{"125.253.114.217", "VN"},
		{"153.72.224.132", "US"},
		{"144.125.238.236", "US"},
		{"47.92.219.102", "CN"},
		{"75.125.95.124", "CA"},
		{"35.180.201.54", "FR"},
		{"149.56.195.17", "CA"},
		{"127.0.0.1", "LO"},
		{"192.168.1.1", "PR"},
	}

	for _, tc := range testCases {
		info := r.Lookup(tc.ip)
		if info.CountryCode != tc.expected {
			t.Errorf("For IP %s expected %s, got %s (%s)", tc.ip, tc.expected, info.CountryCode, info.Country)
		}
	}
}
