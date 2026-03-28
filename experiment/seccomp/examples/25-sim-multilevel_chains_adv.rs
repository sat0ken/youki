use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompArgBuilder, LinuxSeccompBuilder,
    LinuxSeccompOperator, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;

fn main() -> anyhow::Result<()> {
    let mut args1 = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(11u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;
    let mut args2 = LinuxSeccompArgBuilder::default()
        .index(1usize)
        .value(12u64)
        .op(LinuxSeccompOperator::ScmpCmpNe)
        .build()?;

    let mprotect = LinuxSyscallBuilder::default()
        .names(vec!["mprotect".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args1, args2])
        .build()?;

    args1 = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(21u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    args2 = LinuxSeccompArgBuilder::default()
        .index(1usize)
        .value(22u64)
        .op(LinuxSeccompOperator::ScmpCmpNe)
        .build()?;

    let args3 = LinuxSeccompArgBuilder::default()
        .index(2usize)
        .value(23u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    let writev = LinuxSyscallBuilder::default()
        .names(vec!["writev".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args1, args2, args3])
        .build()?;

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKill)
        .syscalls(vec![mprotect, writev])
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
