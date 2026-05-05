mod common;

use common::GATEWAY_BIN;
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(GATEWAY_BIN).args(args).output().unwrap()
}

fn output_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn policy_list_shows_bundled_presets() {
    let output = run(&["policy", "list"]);
    let text = output_text(&output);

    assert!(output.status.success(), "policy list failed:\n{text}");
    assert!(text.contains("claude-code"), "missing claude-code:\n{text}");
    assert!(text.contains("cursor"), "missing cursor:\n{text}");
    assert!(
        text.contains("openai-agents"),
        "missing openai-agents:\n{text}"
    );
}

#[test]
fn policy_init_writes_valid_config() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("gateway.yml");
    let out_s = out.to_str().unwrap();

    let init = run(&["policy", "init", "cursor", "--out", out_s]);
    let init_text = output_text(&init);
    assert!(init.status.success(), "policy init failed:\n{init_text}");
    assert!(out.exists(), "policy init did not create {out_s}");

    let validate = run(&["validate", out_s]);
    let validate_text = output_text(&validate);
    assert!(
        validate.status.success(),
        "generated policy did not validate:\n{validate_text}"
    );

    let yaml = std::fs::read_to_string(out).unwrap();
    assert!(yaml.contains("agents:"), "missing agents section:\n{yaml}");
    assert!(yaml.contains("cursor:"), "missing cursor policy:\n{yaml}");
    assert!(
        yaml.contains("approval_required:"),
        "missing HITL policy:\n{yaml}"
    );
}

#[test]
fn policy_init_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("gateway.yml");
    let out_s = out.to_str().unwrap();
    std::fs::write(&out, "sentinel").unwrap();

    let output = run(&["policy", "init", "cursor", "--out", out_s]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "policy init unexpectedly overwrote file:\n{text}"
    );
    assert!(
        text.contains("already exists"),
        "missing overwrite error:\n{text}"
    );
    assert_eq!(std::fs::read_to_string(out).unwrap(), "sentinel");
}

#[test]
fn policy_init_force_overwrites_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("gateway.yml");
    let out_s = out.to_str().unwrap();
    std::fs::write(&out, "sentinel").unwrap();

    let output = run(&["policy", "init", "claude", "--out", out_s, "--force"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "policy init --force failed:\n{text}"
    );
    let yaml = std::fs::read_to_string(out).unwrap();
    assert_ne!(yaml, "sentinel");
    assert!(
        yaml.contains("claude-code:"),
        "missing claude-code:\n{yaml}"
    );
}

#[test]
fn policy_init_supports_openai_alias() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("gateway.yml");
    let out_s = out.to_str().unwrap();

    let output = run(&["policy", "init", "openai-agent", "--out", out_s]);
    let text = output_text(&output);

    assert!(output.status.success(), "policy alias failed:\n{text}");
    let yaml = std::fs::read_to_string(out).unwrap();
    assert!(
        yaml.contains("openai-agent:"),
        "missing openai-agent policy:\n{yaml}"
    );
    assert!(
        yaml.contains("default_policy:"),
        "missing safe fallback policy:\n{yaml}"
    );
}

#[test]
fn policy_init_unknown_policy_fails() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("gateway.yml");
    let out_s = out.to_str().unwrap();

    let output = run(&["policy", "init", "missing", "--out", out_s]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "unknown policy unexpectedly succeeded:\n{text}"
    );
    assert!(text.contains("unknown policy"), "missing error:\n{text}");
    assert!(!out.exists(), "unknown policy should not create a file");
}
