use zeroclaw_api::runtime_traits::ShellDialect;
use zeroclaw_config::policy::{CommandRiskLevel, SecurityPolicy};

fn powershell_policy() -> SecurityPolicy {
    let mut policy = SecurityPolicy::default();
    policy
        .allowed_commands
        .extend(["write-output", "get-date", "get-childitem", "get-location"].map(str::to_string));
    policy
}

#[test]
fn powershell_expressions_hidden_behind_allowed_commands_fail_closed() {
    let policy = powershell_policy();

    for command in [
        "echo ([System.IO.File]::Delete('important.txt'))",
        "Write-Output $(Remove-Item important.txt)",
        "Write-Output safe; Remove-Item important.txt",
        "Write-Output safe | Invoke-Expression",
        "Write-Output & $command",
        "Write-Output { Remove-Item important.txt }",
        "Write-Output \"safe\\\"; Remove-Item important.txt",
        "Get-ChildItem $PSHOME",
        "Get-ChildItem Env:",
        "Write-Output $PSHOME | Get-ChildItem",
    ] {
        assert_eq!(
            policy.command_risk_level_for_shell(command, ShellDialect::PowerShell),
            CommandRiskLevel::High,
            "unsupported PowerShell syntax must be high risk: {command:?}"
        );
        assert!(
            policy
                .validate_command_execution_for_shell(command, false, ShellDialect::PowerShell,)
                .is_err(),
            "PowerShell expression bypass must be rejected: {command:?}"
        );
    }
}

#[test]
fn documented_read_only_powershell_commands_pass_default_risk_gates() {
    let policy = powershell_policy();

    for command in [
        "Write-Output safe",
        "Get-Date",
        "Get-ChildItem",
        "Get-Location",
        "Write-Output $PSHOME",
        "Write-Output $PSVersionTable.PSVersion",
        "Get-ChildItem | Write-Output",
    ] {
        assert_eq!(
            policy
                .validate_command_execution_for_shell(command, false, ShellDialect::PowerShell,)
                .unwrap_or_else(|error| panic!("{command:?} was rejected: {error}")),
            CommandRiskLevel::Low,
            "read-only PowerShell command should stay low risk: {command:?}"
        );
    }
}

#[test]
fn unknown_powershell_cmdlets_are_high_risk_by_default() {
    let policy = SecurityPolicy {
        allowed_commands: vec!["*".into()],
        ..SecurityPolicy::default()
    };

    assert_eq!(
        policy.command_risk_level_for_shell("Add-Type custom.cs", ShellDialect::PowerShell),
        CommandRiskLevel::High
    );
    assert!(
        policy
            .validate_command_execution_for_shell(
                "Add-Type custom.cs",
                true,
                ShellDialect::PowerShell,
            )
            .is_err()
    );

    for command in [
        ".\\evil.ps1",
        "powershell.exe -Command Get-Date",
        "cmd.exe /C dir",
        "wsl.exe --exec sh -c 'rm important.txt'",
        "customalias important.txt",
    ] {
        assert_eq!(
            policy.command_risk_level_for_shell(command, ShellDialect::PowerShell),
            CommandRiskLevel::High,
            "nested interpreters and scripts must be high risk: {command:?}"
        );
        assert!(
            policy
                .validate_command_execution_for_shell(command, true, ShellDialect::PowerShell,)
                .is_err(),
            "nested interpreter or script must be blocked: {command:?}"
        );
    }
}

#[test]
fn mutation_aliases_and_scoped_variables_are_high_risk() {
    let policy = SecurityPolicy {
        autonomy: zeroclaw_config::policy::AutonomyLevel::Full,
        allowed_commands: vec!["*".into()],
        block_high_risk_commands: true,
        ..SecurityPolicy::default()
    };

    for command in [
        "ac .\\review-proof.txt value",
        "clc .\\review-proof.txt",
        "Write-Output $env:NAME",
        "Write-Output $global:name",
        "Write-Output $script:name",
    ] {
        assert_eq!(
            policy.command_risk_level_for_shell(command, ShellDialect::PowerShell),
            CommandRiskLevel::High,
            "PowerShell trust-boundary case must be high risk: {command:?}"
        );
        assert!(
            policy
                .validate_command_execution_for_shell(command, true, ShellDialect::PowerShell,)
                .is_err(),
            "wildcard must not exempt high-risk PowerShell syntax: {command:?}"
        );
    }

    assert_eq!(
        policy.command_risk_level_for_shell("Write-Output '$env:NAME'", ShellDialect::PowerShell,),
        CommandRiskLevel::Low,
        "single-quoted text must not be parsed as a scoped variable"
    );
}

#[test]
fn wildcard_and_risk_flags_keep_their_existing_approval_semantics() {
    use zeroclaw_config::policy::AutonomyLevel;

    let supervised = SecurityPolicy {
        autonomy: AutonomyLevel::Supervised,
        allowed_commands: vec!["*".into()],
        block_high_risk_commands: false,
        require_approval_for_medium_risk: true,
        ..SecurityPolicy::default()
    };

    assert_eq!(
        supervised
            .validate_command_execution_for_shell(
                "Write-Output \"quoted safe value\" | Select-Object -First 1",
                false,
                ShellDialect::PowerShell,
            )
            .unwrap(),
        CommandRiskLevel::Low
    );

    for command in ["New-Item output.txt", "Copy-Item from.txt to.txt"] {
        assert!(
            supervised
                .validate_command_execution_for_shell(command, false, ShellDialect::PowerShell,)
                .unwrap_err()
                .contains("requires explicit approval")
        );
        assert_eq!(
            supervised
                .validate_command_execution_for_shell(command, true, ShellDialect::PowerShell,)
                .unwrap(),
            CommandRiskLevel::Medium
        );
    }

    for command in [
        "ac output.txt value",
        "wsl.exe --exec echo unsafe",
        "Write-Output $env:NAME",
    ] {
        assert!(
            supervised
                .validate_command_execution_for_shell(command, false, ShellDialect::PowerShell,)
                .unwrap_err()
                .contains("requires explicit approval")
        );
        assert_eq!(
            supervised
                .validate_command_execution_for_shell(command, true, ShellDialect::PowerShell,)
                .unwrap(),
            CommandRiskLevel::High
        );
    }

    let full = SecurityPolicy {
        autonomy: AutonomyLevel::Full,
        ..supervised
    };
    assert_eq!(
        full.validate_command_execution_for_shell(
            "ac output.txt value",
            false,
            ShellDialect::PowerShell,
        )
        .unwrap(),
        CommandRiskLevel::High,
        "full autonomy plus disabled high-risk blocking must remain permissive"
    );
}
