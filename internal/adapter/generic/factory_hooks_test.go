package generic_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spxrogers/agentsync/internal/adapter"
	"github.com/spxrogers/agentsync/internal/adapter/generic"
	"github.com/spxrogers/agentsync/internal/secrets"
	"github.com/spxrogers/agentsync/internal/source"
	"github.com/spxrogers/agentsync/internal/testenv"
	"github.com/spxrogers/agentsync/internal/untrusted"
)

func factorySpec(t *testing.T) generic.Spec {
	t.Helper()
	for _, s := range generic.Specs() {
		if s.Name == "factory" {
			return s
		}
	}
	t.Fatal("factory spec missing")
	return generic.Spec{}
}

func TestRender_Factory_UserMemory(t *testing.T) {
	tmp := t.TempDir()
	a := generic.New(factorySpec(t), generic.Options{TargetRoot: tmp})
	ops, skips, err := a.Render(secrets.ForRender(source.Canonical{Memory: source.Memory{Body: "policy\n"}}), adapter.ScopeUser, "")
	if err != nil {
		t.Fatal(err)
	}
	op := findOp(ops, ".factory/AGENTS.md")
	if op == nil || op.Path != filepath.Join(tmp, ".factory", "AGENTS.md") {
		t.Fatalf("factory user memory op missing or misplaced: %+v", ops)
	}
	if source.StripManagedBanner(string(op.Content)) != "policy\n" {
		t.Fatalf("factory user memory content = %q", op.Content)
	}
	for _, s := range skips {
		if s.Component == "memory" {
			t.Fatalf("factory user memory must not be skipped: %+v", s)
		}
	}
}

func TestRender_FactoryHooks_SecondsAndForeignKeys(t *testing.T) {
	testenv.RequireContainer(t)
	tmp := t.TempDir()
	hooksPath := filepath.Join(tmp, ".factory", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := []byte("{\n  \"hooksDisabled\": false,\n  \"showHookOutput\": false\n}\n")
	if err := os.WriteFile(hooksPath, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	a := generic.New(factorySpec(t), generic.Options{TargetRoot: tmp})
	c := source.Canonical{Hooks: []source.Hook{
		{Event: untrusted.Wrap("PreToolUse"), Matcher: "Execute", Type: "command", Command: "echo hi", Timeout: 30},
		{Event: untrusted.Wrap("PostCompact"), Type: "command", Command: "echo no"},
	}}
	ops, skips, err := a.Render(secrets.ForRender(c), adapter.ScopeUser, "")
	if err != nil {
		t.Fatal(err)
	}
	var sawPostCompact bool
	for _, s := range skips {
		if s.Component == "hook" && s.Name == "PostCompact" {
			sawPostCompact = true
		}
	}
	if !sawPostCompact {
		t.Fatalf("PostCompact must be skipped, not written; skips=%v", skips)
	}
	if err := a.Apply(ops, adapter.PassThroughWriter{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse hooks.json: %v\n%s", err, raw)
	}
	if doc["hooksDisabled"] != false || doc["showHookOutput"] != false {
		t.Fatalf("foreign keys not preserved: %#v", doc)
	}
	if _, ok := doc["PostCompact"]; ok {
		t.Fatal("PostCompact was written; Factory has no such event")
	}
	groups, _ := doc["PreToolUse"].([]any)
	if len(groups) != 1 {
		t.Fatalf("PreToolUse = %#v", doc["PreToolUse"])
	}
	group := groups[0].(map[string]any)
	handlers := group["hooks"].([]any)
	handler := handlers[0].(map[string]any)
	if handler["timeout"] != float64(30) {
		t.Fatalf("timeout = %#v; Factory counts seconds, want 30", handler["timeout"])
	}
	if handler["command"] != "echo hi" {
		t.Fatalf("command = %#v", handler["command"])
	}
}

func TestIngest_FactoryHooks_FromSettingsFallback(t *testing.T) {
	testenv.RequireContainer(t)
	tmp := t.TempDir()
	settings := filepath.Join(tmp, ".factory", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
	  "hooks": {
	    "SessionStart": [ { "matcher": "", "hooks": [ { "type": "command", "command": "bd prime", "timeout": 3 } ] } ]
	  }
	}`
	if err := os.WriteFile(settings, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := generic.New(factorySpec(t), generic.Options{TargetRoot: tmp})
	got, err := a.Ingest(adapter.ScopeUser, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hooks) != 1 || got.Hooks[0].Command != "bd prime" || got.Hooks[0].Timeout != 3 {
		t.Fatalf("settings.json fallback = %+v", got.Hooks)
	}
	if got.Hooks[0].Event.Unverified() != "SessionStart" {
		t.Fatalf("event = %q", got.Hooks[0].Event.Unverified())
	}
}

func TestIngest_FactoryHooks_CommandRegexRefusesEvent(t *testing.T) {
	testenv.RequireContainer(t)
	tmp := t.TempDir()
	hooksPath := filepath.Join(tmp, ".factory", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
	  "PreToolUse": [ { "matcher": "Execute", "commandRegex": "^git ", "hooks": [ { "type": "command", "command": "echo hi" } ] } ]
	}`
	if err := os.WriteFile(hooksPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var warn bytes.Buffer
	a := generic.New(factorySpec(t), generic.Options{TargetRoot: tmp, Stderr: &warn})
	got, err := a.Ingest(adapter.ScopeUser, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hooks) != 0 {
		t.Fatalf("commandRegex must leave the event uncaptured, got %+v", got.Hooks)
	}
	refused, err := a.RefusedHookEvents(adapter.ScopeUser, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) != 1 || refused[0] != "PreToolUse" {
		t.Fatalf("semantic refusal = %v", refused)
	}
	if !strings.Contains(warn.String(), "commandRegex") {
		t.Fatalf("warning = %q", warn.String())
	}
}
