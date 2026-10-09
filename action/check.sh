#!/usr/bin/env bash
# Runs isitfixed for the GitHub Action (see action.yml) and turns its JSON
# report into a step summary, annotations and step outputs.
set -euo pipefail

files="$INPUT_FILES"
if [[ -z "${files//[[:space:]]/}" && ( "${GITHUB_EVENT_NAME:-}" == pull_request || "${GITHUB_EVENT_NAME:-}" == pull_request_target ) ]]; then
  # actions/checkout fetches one commit by default; fetch the base so it can be diffed.
  git fetch --no-tags --depth=1 origin "$BASE_SHA"
  files=$(git diff --name-only --diff-filter=AM "$BASE_SHA" HEAD -- '*.json')
fi

# shortcut: paths and args are split on whitespace, so they cannot contain spaces.
set -f
file_args=()
for f in $files; do file_args+=(--file "$f"); done
# shellcheck disable=SC2206 # word splitting of args is intended
extra_args=($INPUT_ARGS)
set +f

if [[ ${#file_args[@]} -eq 0 ]]; then
  echo "::notice title=isitfixed::no advisory files to check"
  printf 'errors=0\nwarnings=0\nexit-code=0\n' >>"$GITHUB_OUTPUT"
  exit 0
fi

report="$RUNNER_TEMP/isitfixed-report.json"
code=0
"$RUNNER_TEMP/isitfixed" check --format json ${extra_args[@]+"${extra_args[@]}"} "${file_args[@]}" >"$report" || code=$?
echo "exit-code=$code" >>"$GITHUB_OUTPUT"

if [[ ! -s "$report" ]] || ! jq -e '.totals' "$report" >/dev/null 2>&1; then
  echo "::error title=isitfixed::isitfixed exited with status $code without a report (see the log above)"
  exit 2
fi

jq -r '"errors=\(.totals.errors)", "warnings=\(.totals.warnings)"' "$report" >>"$GITHUB_OUTPUT"

# Annotations: errors and checks that could not run as ::error, warnings as ::warning.
jq -r '
  def msg: gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A");
  def prop: msg | gsub(":"; "%3A") | gsub(","; "%2C");
  .advisories[] | . as $a
  | (if .error then "::error file=\($a.source | prop),title=\($a.id | prop) could not be read::\(.error | msg)" else empty end),
    (.findings[] | select(.severity != "info")
     | (if .severity == "warning" then "warning" else "error" end) as $level
     | (if .severity == "failed" then " (could not check)" else "" end) as $suffix
     | "::\($level) file=\($a.source | prop),title=\("\(.check) \(.slug)\($suffix)" | prop)::\(.message | msg)")
' "$report"

# Step summary: one table row per finding, including infos.
jq -r '
  def cell: tostring | gsub("[\r\n]+"; " ") | gsub("\\|"; "\\|");
  .totals as $t
  | [.advisories[] | . as $a
     | (if .error then [$a.source, "could not read", "", "", .error] else empty end),
       (if .skipped then [$a.source, "skipped", "", "", .skipped] else empty end),
       (.findings[] | [$a.source, .severity, "\(.check) \(.slug)", ((.ecosystem // "") + " " + (.package // "")), .message])
    ] as $rows
  | "### isitfixed",
    "",
    "\($t.advisories) \(if $t.advisories == 1 then "advisory" else "advisories" end) checked: \($t.errors) errors, \($t.warnings) warnings, \($t.infos) info"
      + (if $t.could_not_check > 0 then ", \($t.could_not_check) could not be checked" else "" end)
      + (if $t.failed > 0 then ", \($t.failed) could not be read" else "" end)
      + (if $t.skipped > 0 then ", \($t.skipped) skipped" else "" end),
    "",
    if ($rows | length) == 0 then "No findings." else
      "| File | Severity | Check | Package | Message |",
      "|---|---|---|---|---|",
      ($rows[] | map(cell) | "| \(.[0]) | \(.[1]) | \(.[2]) | \(.[3] | ltrimstr(" ")) | \(.[4]) |")
    end
' "$report" >>"$GITHUB_STEP_SUMMARY"

if [[ $code -eq 1 && "$INPUT_FAIL_ON_ERROR" == false ]]; then
  exit 0
fi
exit "$code"
