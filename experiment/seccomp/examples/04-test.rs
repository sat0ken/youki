use nix::libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompArgBuilder, LinuxSeccompBuilder,
    LinuxSeccompOperator, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;
use std::io::stderr;

fn main() -> anyhow::Result<()> {
    let s_size_max = isize::MAX;
    // s_size_max = 0;

    let stdout = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(STDOUT_FILENO as u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;
    let stderr = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(STDERR_FILENO as u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;
    let args2 = LinuxSeccompArgBuilder::default()
        .index(1usize)
        .value(0u64)
        .op(LinuxSeccompOperator::ScmpCmpNe)
        .build()?;
    let args3 = LinuxSeccompArgBuilder::default()
        .index(2usize)
        .value(s_size_max as u64)
        .op(LinuxSeccompOperator::ScmpCmpLt)
        .build()?;

    let write1 = LinuxSyscallBuilder::default()
        .names(vec!["write".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![stdout, args2, args3])
        .build()?;

    let write2 = LinuxSyscallBuilder::default()
        .names(vec!["write".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![stderr, args2, args3])
        .build()?;

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKillThread)
        .syscalls(vec![write1, write2])
        .build()?;
    let inst_data = SeccompProgramPlan::try_from(spec_seccomp)?;
    let mut seccomp = Seccomp::new();
    if !inst_data.flags.is_empty() {
        seccomp.set_flags(inst_data.flags.clone());
    }
    seccomp.filters = Vec::try_from(inst_data)?;
    seccomp.print_bpf();
    seccomp.export_bpf(&mut io::stdout())?;
    Ok(())
}
