package versions

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		eco, a, b string
		want      int
	}{
		// Maven ComparableVersion rules
		{Maven, "2.2.0", "2.2.0.RELEASE", 0},
		{Maven, "2.2.10.RELEASE", "2.2.10", 0},
		{Maven, "1.0", "1.0.0", 0},
		{Maven, "1.0-final", "1.0", 0},
		{Maven, "1.0-ga", "1.0", 0},
		{Maven, "1.0-alpha1", "1.0-beta1", -1},
		{Maven, "1.0-beta1", "1.0-milestone1", -1},
		{Maven, "1.0-milestone1", "1.0-rc1", -1},
		{Maven, "1.0-rc1", "1.0-cr1", 0},
		{Maven, "1.0-rc1", "1.0-SNAPSHOT", -1},
		{Maven, "1.0-SNAPSHOT", "1.0", -1},
		{Maven, "1.0", "1.0-sp1", -1},
		{Maven, "3.34.7", "3.35.0.CR1", -1},
		{Maven, "3.35.0.CR1", "3.35.0", -1},
		{Maven, "3.35.1", "3.35.1.1", -1},
		{Maven, "3.35.1.1", "3.35.2", -1},
		{Maven, "3.27.10", "3.27.9", 1},
		{Maven, "2.2.10.RELEASE", "2.2.9.RELEASE", 1},
		{Maven, "0", "1.0", -1},
		// semver ecosystems
		{Go, "1.10.20", "v1.10.20", 0},
		{Go, "v2.0.0+incompatible", "2.0.0", 0},
		{Go, "1.10.0-rc1", "1.10.0", -1},
		{Go, "1.9.9", "1.10.0", -1},
		{Go, "0.0.0-20230101000000-abcdefabcdef", "0.1.0", -1},
		{Npm, "1.2.3-beta.2", "1.2.3-beta.11", -1},
		{Npm, "1.2.3", "1.2.3+build5", 0},
		{Crates, "0.10.0", "0.9.9", 1},
		{Crates, "1.0.0-alpha", "1.0.0", -1},
	}
	for _, tt := range tests {
		if got := Compare(tt.eco, tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d", tt.eco, tt.a, tt.b, got, tt.want)
		}
		if got := Compare(tt.eco, tt.b, tt.a); got != -tt.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d (reverse)", tt.eco, tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestSort(t *testing.T) {
	vs := []string{"3.35.2", "3.34.7", "3.35.0.CR1", "3.35.0", "3.35.1.1", "3.35.1", "3.9.0"}
	Sort(Maven, vs)
	want := []string{"3.9.0", "3.34.7", "3.35.0.CR1", "3.35.0", "3.35.1", "3.35.1.1", "3.35.2"}
	for i := range want {
		if vs[i] != want[i] {
			t.Fatalf("Sort = %v, want %v", vs, want)
		}
	}
}

func TestLine(t *testing.T) {
	tests := []struct{ eco, v, want string }{
		{Go, "v1.10.20", "1.10"},
		{Go, "1.10.0-rc1", "1.10"},
		{Maven, "3.27.3.1", "3.27"},
		{Maven, "3.28.0.CR1", "3.28"},
		{Maven, "2.2.10.RELEASE", "2.2"},
		{Maven, "20230101", "20230101"},
		{Maven, "1-beta", "1"},
		{Npm, "0.3.04", "0.3"},
		{Crates, "1.0.0-alpha.1", "1.0"},
		{Maven, "RELEASE", ""},
	}
	for _, tt := range tests {
		if got := Line(tt.eco, tt.v); got != tt.want {
			t.Errorf("Line(%s, %q) = %q, want %q", tt.eco, tt.v, got, tt.want)
		}
	}
}

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		eco, v string
		want   bool
	}{
		{Maven, "3.28.0.CR1", true},
		{Maven, "1.0-M1", true},
		{Maven, "1.0-alpha-2", true},
		{Maven, "2.2.10.RELEASE", false},
		{Maven, "3.27.3.1", false},
		{Maven, "1.0.Final", false},
		{Maven, "1.0-SNAPSHOT", true},
		{Go, "1.10.0-rc1", true},
		{Go, "1.10.0", false},
		{Npm, "1.0.0+build.1", false},
		{Crates, "1.0.0-alpha.1", true},
	}
	for _, tt := range tests {
		if got := IsPrerelease(tt.eco, tt.v); got != tt.want {
			t.Errorf("IsPrerelease(%s, %q) = %v, want %v", tt.eco, tt.v, got, tt.want)
		}
	}
}
