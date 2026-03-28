use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompArgBuilder, LinuxSeccompBuilder,
    LinuxSeccompOperator, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;

fn main() -> anyhow::Result<()> {
    let s_size_max = isize::MAX;

    let openat = LinuxSyscallBuilder::default()
        .names(vec!["openat".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()?;
    let close = LinuxSyscallBuilder::default()
        .names(vec!["close".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()?;

    let mut args1 = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(0u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;
    let mut args2 = LinuxSeccompArgBuilder::default()
        .index(1usize)
        .value(0u64)
        .op(LinuxSeccompOperator::ScmpCmpNe)
        .build()?;
    let mut args3 = LinuxSeccompArgBuilder::default()
        .index(2usize)
        .value(s_size_max as u64)
        .op(LinuxSeccompOperator::ScmpCmpLt)
        .build()?;

    let read = LinuxSyscallBuilder::default()
        .names(vec!["writev".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args1, args2, args3])
        .build()?;
    let write = LinuxSyscallBuilder::default()
        .names(vec!["writev".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args1, args2, args3])
        .build()?;
    let rt_sigreturn = LinuxSyscallBuilder::default()
        .names(vec!["rt_sigreturn".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()?;

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKill)
        .syscalls(vec![
            openat,
            close.clone(),
            read,
            write.clone(),
            write.clone(),
            close.clone(),
            rt_sigreturn,
        ])
        .build()?;
    let inst_data = SeccompProgramPlan::try_from(spec_seccomp)?;
    let mut seccomp = Seccomp::new();
    if !inst_data.flags.is_empty() {
        seccomp.set_flags(inst_data.flags.clone());
    }
    seccomp.filters = Vec::try_from(inst_data)?;
    seccomp.export_bpf(&mut io::stdout())?;

    Ok(())
}
