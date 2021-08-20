/*
Copyright 2020-2021 The UnDistro authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package util

import (
	"testing"
)

var tests = []struct{ in, out string }{
	{"simple test", "simple-test"},
	{"I'm go developer", "i-m-go-developer"},
	{"Simples código em go", "simples-codigo-em-go"},
	{"日本語の手紙をテスト", "日本語の手紙をテスト"},
	{"--->simple test<---", "simple-test"},
	{"NoSchedule", "no-schedule"},
}

func TestSlugify(t *testing.T) {
	for _, test := range tests {
		if out := Slugify(test.in); out != test.out {
			t.Errorf("%q: %q != %q", test.in, out, test.out)
		}
	}
}

func TestSlugifyf(t *testing.T) {
	for _, test := range tests {
		t.Run(test.out, func(t *testing.T) {
			if out := Slugifyf("%s", test.in); out != test.out {
				t.Errorf("%q: %q != %q", test.in, out, test.out)
			}
		})
	}
}
