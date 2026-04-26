use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompArgBuilder, LinuxSeccompBuilder,
    LinuxSeccompOperator, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;

fn main() -> anyhow::Result<()> {
    let mut args_vec = vec![];

    for i in 0..5 {
        let args = LinuxSeccompArgBuilder::default()
            .index(0usize)
            .value(i as u64)
            .op(LinuxSeccompOperator::ScmpCmpEq)
            .build()?;
        args_vec.push(args);
    }

    let mut args = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(0u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    // let read = LinuxSyscallBuilder::default()
    //     .names(vec!["read".to_string()])
    //     .action(LinuxSeccompAction::ScmpActAllow)
    //     .args(vec![args])
    //     .build()?;

    args = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(1u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    let write1 = LinuxSyscallBuilder::default()
        .names(vec!["write".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(args_vec)
        .build()?;

    args = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(2u64)
        .op(LinuxSeccompOperator::ScmpCmpEq)
        .build()?;

    let args1 = LinuxSeccompArgBuilder::default()
        .index(0usize)
        .value(3u64)
        .op(LinuxSeccompOperator::ScmpCmpGe)
        .build()?;

    let write2 = LinuxSyscallBuilder::default()
        .names(vec!["write".to_string()])
        .action(LinuxSeccompAction::ScmpActAllow)
        .args(vec![args])
        .build()?;

    // let close = LinuxSyscallBuilder::default()
    //     .names(vec!["close".to_string()])
    //     .action(LinuxSeccompAction::ScmpActAllow)
    //     .build()?;
    // let rt_sigreturn = LinuxSyscallBuilder::default()
    //     .names(vec!["rt_sigreturn".to_string()])
    //     .action(LinuxSeccompAction::ScmpActAllow)
    //     .build()?;

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKillProcess)
        .syscalls(vec![write1])
        .build()?;
    let inst_data = SeccompProgramPlan::try_from(spec_seccomp)?;
    let mut seccomp = Seccomp::new();
    if !inst_data.flags.is_empty() {
        seccomp.set_flags(inst_data.flags.clone());
    }
    seccomp.filters = Vec::try_from(inst_data)?;
    // seccomp.export_bpf(&mut io::stdout())?;
    seccomp.print_bpf();

    Ok(())
}
