// Copyright 2020 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"regexp"
	"testing"

	"github.com/saferwall/saferwall/pkg/utils"
)

var rePrototypetests = []struct {
	in  string
	out int
}{
	{"C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.19041.0\\um\\fileapi.h", 94},
	{"C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.19041.0\\um\\processthreadsapi.h", 85},
}

func TestGetAPIPrototypes(t *testing.T) {
	for _, tt := range rePrototypetests {
		t.Run(tt.in, func(t *testing.T) {
			data, err := utils.ReadAll(tt.in)
			if err != nil {
				t.Errorf("TestGetAPIPrototypes(%s) failed, got: %s", tt.in, err)
			}

			r := regexp.MustCompile(RegAPIs)
			matches := r.FindAllString(string(data), -1)
			got := len(matches)
			if got != tt.out {
				t.Errorf("TestGetAPIPrototypes(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}
