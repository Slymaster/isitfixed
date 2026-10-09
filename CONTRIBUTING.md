# Contributing

Thanks for helping make advisory data more accurate.

- **Bug reports and false positives** are the most useful contributions. Please
  include the advisory ID, the finding (`--format json` output is ideal) and
  why you believe it is wrong.
- **Code**: run `gofmt`, `go vet ./...` and `go test ./...` before opening a
  pull request. Unit tests must work offline; tests that hit real registries go
  in `cmd/isitfixed/integration_test.go` and only run with
  `ISITFIXED_NETWORK=1`.
- **New checks** need a stable ID, a row in the README's checks table, and a
  test showing both a finding and a non-finding.
- Keep precision first: a check that is right 95% of the time and silent
  otherwise is better than one that flags everything.

If you report advisory errors found with isitfixed upstream (for example to
github/advisory-database), please verify them by hand first.
