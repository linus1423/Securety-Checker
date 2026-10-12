package check

import "testing"

func TestWeakPassword(t *testing.T) {
	cases := []struct {
		value string
		weak  bool
	}{
		{"password", true},    // default
		{"Admin", true},       // default, case-insensitive
		{"hunter2", true},     // too short
		{"12345678", true},    // default-listed
		{"00000000", true},    // only digits
		{"abcdefgh", true},    // only lowercase letters
		{"", false},           // empty: value injected elsewhere
		{"${DB_PASS}", false}, // placeholder
		{"Gx7!qL29pZ", false}, // strong
		{"S3cure-Pass_2024", false},
	}
	for _, c := range cases {
		if _, weak := weakPassword(c.value); weak != c.weak {
			t.Errorf("weakPassword(%q) weak = %v; want %v", c.value, weak, c.weak)
		}
	}
}

func TestPasswordKeyRe(t *testing.T) {
	match := []string{"DB_PASSWORD", "mysql_passwd", "PWD", "ROOT_PW", "app-pwd-value"}
	noMatch := []string{"API_KEY", "TOKEN", "USERNAME", "HOST"}
	for _, k := range match {
		if !passwordKeyRe.MatchString(k) {
			t.Errorf("passwordKeyRe should match %q", k)
		}
	}
	for _, k := range noMatch {
		if passwordKeyRe.MatchString(k) {
			t.Errorf("passwordKeyRe should not match %q", k)
		}
	}
}
