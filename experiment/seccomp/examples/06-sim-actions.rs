use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;

fn main() -> anyhow::Result<()> {
    let read = LinuxSyscallBuilder::default()
        .names(vec!["read".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()?;
    let rt_sigreturn = LinuxSyscallBuilder::default()
        .names(vec!["rt_sigreturn".to_string()])
        .action(LinuxSeccompAction::ScmpActLog)
        .build()?;
    let write = LinuxSyscallBuilder::default()
        .names(vec!["write".to_string()])
        .action(LinuxSeccompAction::ScmpActErrno)
        .errno_ret(1u32)
        .build()?;
    let close = LinuxSyscallBuilder::default()
        .names(vec!["close".to_string()])
        .action(LinuxSeccompAction::ScmpActTrap)
        .build()?;
    let openat = LinuxSyscallBuilder::default()
        .names(vec!["openat".to_string()])
        .action(LinuxSeccompAction::ScmpActTrace)
        .errno_ret(1234u32)
        .build()?;
    let fstatfs = LinuxSyscallBuilder::default()
        .names(vec!["fstatfs".to_string()])
        .action(LinuxSeccompAction::ScmpActKillProcess)
        .build()?;

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKill)
        .syscalls(vec![read, rt_sigreturn, write, close, openat, fstatfs])
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
