use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompArgBuilder, LinuxSeccompBuilder,
    LinuxSeccompOperator, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;

fn main() -> anyhow::Result<()> {
    let mut args = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(0u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    let read = LinuxSyscallBuilder::default()
        .names(vec!["read".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args])
        .build()?;

    args = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(1u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    let write1 = LinuxSyscallBuilder::default()
        .names(vec!["write".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args])
        .build()?;

    args = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(2u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    let write2 = LinuxSyscallBuilder::default()
        .names(vec!["write".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args])
        .build()?;

    let close = LinuxSyscallBuilder::default()
        .names(vec!["close".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()?;
    let rt_sigreturn = LinuxSyscallBuilder::default()
        .names(vec!["rt_sigreturn".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()?;

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKill)
        .syscalls(vec![read, write1, write2, close, rt_sigreturn])
        .build()?;
    let inst_data = SeccompProgramPlan::try_from(spec_seccomp)?;
    let mut seccomp = Seccomp::new();
    if !inst_data.flags.is_empty() {
        seccomp.set_flags(inst_data.flags.clone());
    }
    seccomp.filters = Vec::try_from(inst_data)?;
    // for filter in &seccomp.filters {
    //     println!(
    //         "code: {:02x}, jt: {:02x}, jf: {:02x}, k: {:08x}",
    //         filter.code, filter.offset_jump_true, filter.offset_jump_false, filter.multiuse_field
    //     )
    // }
    seccomp.export_bpf(&mut io::stdout())?;

    Ok(())
}
