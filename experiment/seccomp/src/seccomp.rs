use crate::instruction::*;
use crate::instruction::{Arch, Instruction, SECCOMP_IOC_MAGIC};
use anyhow::Result;
use core::fmt;
use derive_builder::Builder;
use nix::libc::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_SPEC_ALLOW, SECCOMP_FILTER_FLAG_TSYNC,
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
};
use nix::{
    errno::Errno,
    ioctl_readwrite, ioctl_write_ptr, libc,
    libc::{SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_SET_MODE_FILTER},
    unistd,
};
use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompFilterFlag,
    LinuxSeccompOperator,
};
use std::io::Write;
use std::os::raw::c_uchar;
use std::str::FromStr;
use std::{
    mem::MaybeUninit,
    os::{
        raw::{c_long, c_uint, c_ulong, c_ushort, c_void},
        unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("Failed to apply seccomp rules: {0}")]
    Apply(String),
    #[error("valid indices are 0–5")]
    InvalidArgumentSize,
    #[error("Cant ScmpActNotify to default action")]
    InvalidDefaultAction,
    #[error("Cant filter to write system call")]
    InvalidSystemCall,
}

pub struct Seccomp {
    pub filters: Vec<Instruction>,
    pub flags: c_ulong,
}

impl Default for Seccomp {
    fn default() -> Self {
        Seccomp::new()
    }
}

impl Seccomp {
    pub fn new() -> Self {
        Seccomp {
            filters: Vec::new(),
            flags: SECCOMP_FILTER_FLAG_NEW_LISTENER,
        }
    }

    pub fn set_flags(&mut self, flags: Vec<c_ulong>) {
        for flag in flags {
            self.flags |= flag;
        }
    }

    // apply applies the seccomp rules to the current process and return a fd for seccomp notify.
    pub fn apply(&self) -> Result<NotifyFd, SeccompError> {
        let mut prog = Filters {
            len: self.filters.len() as _,
            filter: self.filters.as_ptr(),
        };

        // TODO: Address the case where don't use seccomp notify.
        let notify_fd = unsafe {
            seccomp(
                SECCOMP_SET_MODE_FILTER,
                self.flags,
                &mut prog as *mut _ as *mut c_void,
            )
        };

        Errno::result(notify_fd).map_err(|e| SeccompError::Apply(e.to_string()))?;
        Ok(unsafe { NotifyFd::from_raw_fd(notify_fd as RawFd) })
    }

    pub fn export_bpf<W: Write>(&self, writer: &mut W) -> Result<(), SeccompError> {
        for inst in &self.filters {
            writer
                .write_all(inst.to_bytes().as_slice())
                .map_err(|e| SeccompError::Apply(e.to_string()))?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct NotifyFd {
    fd: RawFd,
}

impl Drop for NotifyFd {
    fn drop(&mut self) {
        unistd::close(self.fd).unwrap()
    }
}

impl FromRawFd for NotifyFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NotifyFd { fd }
    }
}

impl IntoRawFd for NotifyFd {
    fn into_raw_fd(self) -> RawFd {
        let NotifyFd { fd } = self;
        fd
    }
}

impl AsRawFd for NotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl NotifyFd {
    pub fn success(&self, v: i64, notify_id: u64) -> nix::Result<()> {
        let mut resp = SeccompNotifResp {
            id: notify_id,
            val: v,
            error: 0,
            flags: 0,
        };

        unsafe { seccomp_notif_ioctl_send(self.fd, &mut resp as *mut _)? };

        Ok(())
    }
}

// TODO: Rename
#[repr(C)]
#[derive(Debug)]
pub struct SeccompData {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifSizes {
    pub seccomp_notif: u16,
    pub seccomp_notif_resp: u16,
    pub seccomp_data: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

ioctl_readwrite!(seccomp_notif_ioctl_recv, SECCOMP_IOC_MAGIC, 0, SeccompNotif);
ioctl_readwrite!(
    seccomp_notif_ioctl_send,
    SECCOMP_IOC_MAGIC,
    1,
    SeccompNotifResp
);
ioctl_write_ptr!(seccomp_notif_ioctl_id_valid, SECCOMP_IOC_MAGIC, 2, u64);
ioctl_write_ptr!(
    seccomp_notif_ioctl_addfd,
    SECCOMP_IOC_MAGIC,
    3,
    SeccompNotifAddfd
);

pub struct Notification<'f> {
    pub notif: SeccompNotif,
    pub fd: &'f NotifyFd,
}

impl<'f> fmt::Debug for Notification<'f> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.notif, f)
    }
}

impl NotifyFd {
    pub fn recv(&self) -> nix::Result<Notification> {
        let mut res = MaybeUninit::zeroed();
        let notif = unsafe {
            seccomp_notif_ioctl_recv(self.fd, res.as_mut_ptr())?;
            res.assume_init()
        };

        Ok(Notification { notif, fd: self })
    }
}

unsafe fn seccomp(op: c_uint, flags: c_ulong, args: *mut c_void) -> c_long {
    libc::syscall(libc::SYS_seccomp, op, flags, args)
}

#[repr(C)]
struct Filters {
    pub len: c_ushort,
    pub filter: *const Instruction,
}

fn get_syscall_number(arc: &Arch, name: &str) -> Option<u64> {
    match arc {
        Arch::X86 => match syscalls::x86_64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
        Arch::AArch64 => match syscalls::aarch64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
    }
}

// This wrapper type is used to implement the `From` trait while avoiding the orphan rule's restrictions.
pub struct SeccompActionWrapper(pub LinuxSeccompAction);

impl From<SeccompActionWrapper> for u32 {
    fn from(wrapped_action: SeccompActionWrapper) -> Self {
        // Extracts the wrapped LinuxSeccompAction
        let action = wrapped_action.0;
        match action {
            LinuxSeccompAction::ScmpActKill => SECCOMP_RET_KILL_THREAD,
            LinuxSeccompAction::ScmpActTrap => SECCOMP_RET_TRAP,
            LinuxSeccompAction::ScmpActErrno => SECCOMP_RET_ERRNO,
            LinuxSeccompAction::ScmpActTrace => SECCOMP_RET_TRACE,
            LinuxSeccompAction::ScmpActAllow => SECCOMP_RET_ALLOW,
            LinuxSeccompAction::ScmpActKillProcess => SECCOMP_RET_KILL_PROCESS,
            LinuxSeccompAction::ScmpActNotify => SECCOMP_RET_USER_NOTIF,
            LinuxSeccompAction::ScmpActLog => SECCOMP_RET_LOG,
            LinuxSeccompAction::ScmpActKillThread => SECCOMP_RET_KILL_THREAD,
        }
    }
}

impl From<LinuxSeccompOperator> for SeccompCompareOp {
    fn from(op: LinuxSeccompOperator) -> Self {
        match op {
            LinuxSeccompOperator::ScmpCmpNe => SeccompCompareOp::NotEqual,
            LinuxSeccompOperator::ScmpCmpLt => SeccompCompareOp::LessThan,
            LinuxSeccompOperator::ScmpCmpLe => SeccompCompareOp::LessOrEqual,
            LinuxSeccompOperator::ScmpCmpEq => SeccompCompareOp::Equal,
            LinuxSeccompOperator::ScmpCmpGe => SeccompCompareOp::GreaterOrEqual,
            LinuxSeccompOperator::ScmpCmpGt => SeccompCompareOp::GreaterThan,
            LinuxSeccompOperator::ScmpCmpMaskedEq => SeccompCompareOp::MaskedEqual,
        }
    }
}

fn check_seccomp(seccomp: &LinuxSeccomp) -> Result<(), SeccompError> {
    // We don't support notify as default action. After the seccomp filter is
    // created with notify, the container process will have to communicate the
    // returned fd to another process. Therefore, we need the write syscall or
    // otherwise, the write syscall will be block by the seccomp filter causing
    // the container process to hang. `runc` also disallow notify as default
    // action.
    // Note: read and close syscall are also used, because if we can
    // successfully write fd to another process, the other process can choose to
    // handle read/close syscall and allow read and close to proceed as
    // expected.
    if seccomp.default_action() == LinuxSeccompAction::ScmpActNotify {
        // Todo: consider need to porting SeccompError
        return Err(SeccompError::InvalidDefaultAction);
    }

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            if syscall.action() == LinuxSeccompAction::ScmpActNotify {
                for name in syscall.names() {
                    if name == "write" {
                        return Err(SeccompError::InvalidSystemCall);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Converts one chunk (up to 254) of syscalls into a sequence of BPF instructions.
/// The jump offset is complete within this chunk, and it is assumed that the matching instruction (an intermediate BPF_RET or a final BPF_RET)
/// comes immediately after the chunk.
fn syscall_to_bpf_chunk(
    def_action: u32,
    rule_chunk: &&[Rule],
    is_same_action: bool,
) -> Result<Vec<Instruction>, SeccompError> {
    let mut bpf = vec![];

    let n = rule_chunk.len();
    for (i, rule) in rule_chunk.iter().enumerate() {
        let remain = n - i;
        bpf.extend(Rule::build_instruction(
            rule,
            def_action,
            is_same_action,
            remain,
            &rule.syscall,
        )?);
    }

    Ok(bpf)
}

/// Divide the entire rule.syscall into chunks of 254,
/// Construct the BPF instruction sequence so that jt/jf does not exceed 255.
/// Insert BPF_JA + intermediate BPF_RET at the end of non-final chunks.
fn build_syscall_section(
    rules: Vec<Rule>,
    def_action: u32,
) -> Result<Vec<Instruction>, SeccompError> {
    let mut bpf = vec![];
    let chunks: Vec<&[Rule]> = rules.chunks(254).collect();
    let last_idx = chunks.len().saturating_sub(1);

    let mut action = 0;
    let mut is_same_action = false;
    // check filter action is same to all system call or not
    match check_same_action(&rules) {
        Some(check) => {
            action = check;
            is_same_action = true;
        }
        None => {}
    }
    let has_args = rules.iter().any(|r| !r.rule_args.is_empty());

    for (i, chunk) in chunks.iter().enumerate() {
        bpf.extend(syscall_to_bpf_chunk(def_action, chunk, is_same_action)?);
        if i != last_idx {
            // bpf.push(Instruction::stmt(BPF_JMP | BPF_JA, 1));
            bpf.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
        }
    }
    if is_same_action {
        if !has_args {
            bpf.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
            bpf.push(Instruction::stmt(BPF_RET | BPF_K, action));
        }
    }
    bpf.push(Instruction::stmt(BPF_RET | BPF_K, 0));

    Ok(bpf)
}

// check all action for system call is same or not
fn check_same_action(rules: &[Rule]) -> Option<u32> {
    let first = rules.first()?.action;
    if rules.iter().all(|r| r.action == first) {
        Some(first)
    } else {
        None
    }
}

#[derive(Debug, Default)]
pub struct SeccompProgramPlan {
    pub arc: Arch,
    pub def_action: u32,
    pub def_errno_ret: u32,
    pub flags: Vec<c_ulong>,
    pub rules: Vec<Rule>,
}

impl TryFrom<SeccompProgramPlan> for Vec<Instruction> {
    type Error = SeccompError;
    fn try_from(inst_data: SeccompProgramPlan) -> Result<Self, SeccompError> {
        let bpf_prog = build_syscall_section(inst_data.rules.clone(), inst_data.def_action)?;
        let mut all_bpf_prog =
            gen_validate(&inst_data.arc, inst_data.def_action, bpf_prog.len() - 2);
        all_bpf_prog.extend(bpf_prog);
        Ok(all_bpf_prog)
    }
}

impl TryFrom<LinuxSeccomp> for SeccompProgramPlan {
    type Error = SeccompError;

    fn try_from(seccomp: LinuxSeccomp) -> Result<Self, SeccompError> {
        let mut data: SeccompProgramPlan = Default::default();
        check_seccomp(&seccomp)?;

        if seccomp.default_action() == LinuxSeccompAction::ScmpActErrno {
            if let Some(ret) = seccomp.default_errno_ret() {
                data.def_action = seccomp.default_action().as_u32(Option::from(ret));
            }
        } else {
            data.def_action = u32::from(seccomp.default_action());
        }

        if let Some(flags) = seccomp.flags() {
            for flag in flags {
                match flag {
                    LinuxSeccompFilterFlag::SeccompFilterFlagLog => {
                        data.flags.push(SECCOMP_FILTER_FLAG_LOG)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagTsync => {
                        data.flags.push(SECCOMP_FILTER_FLAG_TSYNC)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => {
                        data.flags.push(SECCOMP_FILTER_FLAG_SPEC_ALLOW)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv => {
                        data.flags.push(SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)
                    }
                }
            }
        }

        if let Some(archs) = seccomp.architectures() {
            for &arch in archs {
                // Todo: consider support other Arch
                match arch {
                    OciSpecArch::ScmpArchX86_64 => data.arc = Arch::X86,
                    OciSpecArch::ScmpArchAarch64 => data.arc = Arch::AArch64,
                    _ => {}
                }
            }
        }

        /*
        Todo: how to impl this?
        ctx.set_ctl_nnp(false)
        .map_err(|err| SeccompError::SetCtlNnp { source: err })?;
         */
        if let Some(syscalls) = seccomp.syscalls() {
            for syscall in syscalls {
                for name in syscall.names() {
                    let mut rule = Rule::default();
                    rule.is_notify = rule.action == SECCOMP_RET_USER_NOTIF;
                    if syscall.action().eq(&LinuxSeccompAction::ScmpActErrno)
                        || syscall.action().eq(&LinuxSeccompAction::ScmpActTrace)
                    {
                        if let Some(errno_ret) = syscall.errno_ret() {
                            rule.action = syscall.action().as_u32(Option::from(errno_ret));
                        }
                    } else {
                        rule.action = u32::from(syscall.action());
                    }
                    rule.syscall = get_syscall_number(&data.arc, name).unwrap();

                    if let Some(args) = syscall.args() {
                        if syscall.args().iter().len() > 6 {
                            return Err(SeccompError::InvalidArgumentSize);
                        }
                        for (i, arg) in args.iter().enumerate() {
                            let mut rule_args = RuleArgs::default();
                            rule_args.index = i as u8;
                            rule_args.values = arg.value();
                            rule_args.op = SeccompCompareOp::from(arg.op());
                            rule.rule_args.push(rule_args);
                        }
                    }
                    data.rules.push(rule);
                }
            }
            data.rules.sort_by_key(|rule| rule.syscall);
        }
        Ok(data)
    }
}

// RuleArgs for check argument of system call
#[derive(Builder, Clone, Debug, Default)]
pub struct RuleArgs {
    pub index: u8,
    pub values: u64,
    pub op: SeccompCompareOp,
}

#[derive(Builder, Clone, Debug, Default)]
#[builder(setter(into))]
pub struct Rule {
    pub syscall: u64,
    pub action: u32,
    #[builder(default)]
    pub errno_ret: u32,
    #[builder(default)]
    pub rule_args: Vec<RuleArgs>,
    #[builder(default)]
    pub is_notify: bool,
}

#[allow(clippy::too_many_arguments)]
impl Rule {
    pub fn new(
        syscall: u64,
        action: u32,
        errno_ret: u32,
        rule_args: Vec<RuleArgs>,
        is_notify: bool,
    ) -> Self {
        Self {
            syscall,
            action,
            errno_ret,
            rule_args,
            is_notify,
        }
    }

    fn jump_cnt(rule: &Rule, mut jump_num: usize) -> c_uchar {
        if rule.rule_args.len() == 0 {
            jump_num as c_uchar
        } else {
            for rule_args in rule.rule_args.iter() {
                match rule_args.op {
                    SeccompCompareOp::Equal
                    | SeccompCompareOp::NotEqual
                    | SeccompCompareOp::MaskedEqual => jump_num += 4,
                    SeccompCompareOp::GreaterThan
                    | SeccompCompareOp::GreaterOrEqual
                    | SeccompCompareOp::LessThan
                    | SeccompCompareOp::LessOrEqual => jump_num += 5,
                }
            }
            jump_num as c_uchar
        }
    }

    fn build_instruction_with_args(
        rule: &Rule,
        syscall: &u64,
        def_action: u32,
    ) -> Result<Vec<Instruction>, SeccompError> {
        let mut bpf_prog = vec![];
        for rule_arg in rule.rule_args.iter() {
            let offset = seccomp_data_args_offset(rule_arg.index)?;
            match rule_arg.op {
                SeccompCompareOp::NotEqual => {
                    // if system call number is not match, skip args check jf 4 to default action
                    bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 5, *syscall as c_uint));
                    // upper 32bit check of args
                    bpf_prog.push(Instruction::stmt(
                        BPF_LD | BPF_W | BPF_ABS,
                        (offset + 4).into(),
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        0,
                        2,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    // lower 32bit check of args
                    bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        1,
                        0,
                        rule_arg.values as c_uint,
                    ));

                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
                }
                SeccompCompareOp::LessThan => {
                    // if system call number is not match, skip args check jf 4 to default action
                    bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 5, *syscall as c_uint));
                    // upper 32bit check of args
                    bpf_prog.push(Instruction::stmt(
                        BPF_LD | BPF_W | BPF_ABS,
                        (offset + 4).into(),
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGE | BPF_K,
                        0,
                        4,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        0,
                        2,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    // lower 32bit check of args
                    bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGE | BPF_K,
                        0,
                        1,
                        rule_arg.values as c_uint,
                    ));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
                }
                SeccompCompareOp::LessOrEqual => {
                    bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 5, *syscall as c_uint));
                    // upper 32bit check of args
                    bpf_prog.push(Instruction::stmt(
                        BPF_LD | BPF_W | BPF_ABS,
                        (offset + 4).into(),
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGE | BPF_K,
                        0,
                        4,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        0,
                        2,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    // lower 32bit check of args
                    bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGT | BPF_K,
                        0,
                        1,
                        rule_arg.values as c_uint,
                    ));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
                }
                SeccompCompareOp::Equal => {
                    // if system call number is not match, skip args check jf 4 to default action
                    bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 4, *syscall as c_uint));
                    // upper 32bit check of args
                    bpf_prog.push(Instruction::stmt(
                        BPF_LD | BPF_W | BPF_ABS,
                        (offset + 4).into(),
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        0,
                        2,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    // lower 32bit check of args
                    bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        1,
                        0,
                        rule_arg.values as c_uint,
                    ));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
                }
                SeccompCompareOp::GreaterOrEqual => {
                    // if system call number is not match, skip args check jf 4 to default action
                    bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 5, *syscall as c_uint));
                    // upper 32bit check of args
                    bpf_prog.push(Instruction::stmt(
                        BPF_LD | BPF_W | BPF_ABS,
                        (offset + 4).into(),
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGT | BPF_K,
                        4,
                        0,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        0,
                        2,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    // lower 32bit check of args
                    bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGE | BPF_K,
                        1,
                        0,
                        rule_arg.values as c_uint,
                    ));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
                }
                SeccompCompareOp::GreaterThan => {
                    // if system call number is not match, skip args check jf 4 to default action
                    bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 5, *syscall as c_uint));
                    // upper 32bit check of args
                    bpf_prog.push(Instruction::stmt(
                        BPF_LD | BPF_W | BPF_ABS,
                        (offset + 4).into(),
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGT | BPF_K,
                        4,
                        0,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        0,
                        2,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    // lower 32bit check of args
                    bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
                    bpf_prog.push(Instruction::jump(
                        BPF_JGE | BPF_K,
                        1,
                        0,
                        rule_arg.values as c_uint,
                    ));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
                }
                SeccompCompareOp::MaskedEqual => {
                    // if system call number is not match, skip args check jf 4 to default action
                    bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 6, *syscall as c_uint));

                    // upper 32bit check of args
                    bpf_prog.push(Instruction::stmt(
                        BPF_LD | BPF_W | BPF_ABS,
                        (offset + 4).into(),
                    ));
                    bpf_prog.push(Instruction::stmt(
                        BPF_ALU | BPF_AND | BPF_K,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        0,
                        3,
                        (rule_arg.values >> 32) as c_uint,
                    ));
                    // lower 32bit check of
                    bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
                    bpf_prog.push(Instruction::stmt(
                        BPF_ALU | BPF_AND | BPF_K,
                        rule_arg.values as c_uint,
                    ));
                    bpf_prog.push(Instruction::jump(
                        BPF_JEQ | BPF_K,
                        1,
                        0,
                        rule_arg.values as c_uint,
                    ));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
                    bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
                }
            }
        }

        Ok(bpf_prog)
    }

    pub fn build_instruction(
        rule: &Rule,
        def_action: u32,
        is_same_action: bool,
        jump_num: usize,
        syscall: &u64,
    ) -> Result<Vec<Instruction>, SeccompError> {
        let mut bpf_prog = vec![];
        if rule.rule_args.len() != 0 {
            bpf_prog.extend(Rule::build_instruction_with_args(
                rule, syscall, def_action,
            )?);
        } else {
            if is_same_action {
                bpf_prog.push(Instruction::jump(
                    BPF_JEQ | BPF_K,
                    jump_num as c_uchar,
                    0,
                    *syscall as c_uint,
                ));
            } else {
                bpf_prog.push(Instruction::jump(
                    BPF_JEQ | BPF_K,
                    Self::jump_cnt(rule, 0),
                    1,
                    *syscall as c_uint,
                ));
                bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
            }
        }

        Ok(bpf_prog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_syscall_number_x86() {
        let sys_num = get_syscall_number(&Arch::X86, "read");
        assert_eq!(sys_num.unwrap(), 0);
    }

    #[test]
    fn test_get_syscall_number_aarch64() {
        let sys_num = get_syscall_number(&Arch::AArch64, "read");
        assert_eq!(sys_num.unwrap(), 63);
    }

    #[test]
    fn test_build_instruction_x86() {
        let getcwd = get_syscall_number(&Arch::X86, "getcwd").unwrap();
        let rule = RuleBuilder::default()
            .action(SECCOMP_RET_ALLOW)
            .syscall(getcwd)
            .build()
            .expect("failed to build rule");
        let inst = Rule::build_instruction(&rule, true, 1, &getcwd).unwrap();
        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, getcwd as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_aarch64() {
        let getcwd = get_syscall_number(&Arch::AArch64, "getcwd").unwrap();
        let rule = RuleBuilder::default()
            .action(SECCOMP_RET_ALLOW)
            .syscall(getcwd)
            .build()
            .expect("failed to build rule");
        let inst = Rule::build_instruction(&rule, true, 1, &getcwd).unwrap();
        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, getcwd as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::Equal)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::Equal)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_not_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::NotEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 3, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_not_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::NotEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 3, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_less_than() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessThan)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_less_than() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessThan)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_less_or_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessOrEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGT | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_less_or_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessOrEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGT | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_greater_or_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterOrEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_greater_or_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterOrEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_greater_than() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterThan)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_greater_than() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterThan)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_masked_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::MaskedEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JSET | BPF_K, 3, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JSET | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_masked_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::MaskedEqual)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule.rule_args.len() as u8).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality).unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JSET | BPF_K, 3, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JSET | BPF_K, 1, 0, personality_args as c_uint)
        );
    }
}
