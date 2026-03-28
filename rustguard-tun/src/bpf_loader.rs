//! Minimal BPF ELF loader for the XDP WireGuard filter.
//!
//! Loads the pre-compiled xdp_wg.o, creates the XSKMAP,
//! patches the map fd into the program, loads it, and attaches to an interface.
//!
//! No libbpf. No aya. Just raw bpf() syscalls and ELF parsing.
//! The .o is 1.4KB and never changes.

#![cfg(target_os = "linux")]

use std::io;

/// The pre-compiled BPF object.
const XDP_WG_OBJ: &[u8] = include_bytes!("../bpf/xdp_wg.o");

// BPF syscall commands.
const BPF_MAP_CREATE: u32 = 0;
const BPF_PROG_LOAD: u32 = 5;
const BPF_MAP_UPDATE_ELEM: u32 = 2;

// BPF map types.
const BPF_MAP_TYPE_XSKMAP: u32 = 17;

// BPF program types.
const BPF_PROG_TYPE_XDP: u32 = 6;

// XDP attach flags.
const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;

// ELF constants.
const ET_REL: u16 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_REL: u32 = 9;
const EM_BPF: u16 = 247;

/// A loaded XDP program with its XSKMAP.
pub struct XdpProgram {
    pub prog_fd: i32,
    pub xsks_map_fd: i32,
    ifindex: u32,
}

impl XdpProgram {
    /// Load the XDP WireGuard filter and attach it to an interface.
    pub fn load_and_attach(ifname: &str) -> io::Result<Self> {
        let ifindex = super::xdp::if_nametoindex(ifname)?;

        // 1. Create the XSKMAP.
        let xsks_map_fd = bpf_create_xskmap(64)?;

        // 2. Parse ELF, extract program bytecode, patch map references.
        let insns = match parse_and_patch_elf(XDP_WG_OBJ, xsks_map_fd) {
            Ok(insns) => insns,
            Err(e) => {
                unsafe { libc::close(xsks_map_fd) };
                return Err(e);
            }
        };
        eprintln!("  BPF: parsed ELF, {} insn bytes, map_fd={}", insns.len(), xsks_map_fd);

        // 3. Load BPF program.
        let prog_fd = match bpf_prog_load(&insns) {
            Ok(fd) => fd,
            Err(e) => {
                unsafe { libc::close(xsks_map_fd) };
                return Err(io::Error::new(e.kind(), format!("prog_load ({} insns): {e}", insns.len() / 8)));
            }
        };
        eprintln!("  BPF: program loaded, prog_fd={}", prog_fd);

        // 4. Attach to interface.
        if let Err(e) = attach_xdp(ifindex, prog_fd) {
            unsafe {
                libc::close(prog_fd);
                libc::close(xsks_map_fd);
            }
            return Err(io::Error::new(e.kind(), format!("xdp_attach ifindex={ifindex}: {e}")));
        }
        eprintln!("  BPF: attached to ifindex={}", ifindex);

        Ok(Self {
            prog_fd,
            xsks_map_fd,
            ifindex,
        })
    }

    /// Register an AF_XDP socket fd in the XSKMAP for a given queue.
    pub fn register_xsk(&self, queue_id: u32, xsk_fd: i32) -> io::Result<()> {
        bpf_map_update(self.xsks_map_fd, &queue_id, &xsk_fd)
    }
}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        // Detach XDP program from interface.
        let _ = detach_xdp(self.ifindex);
        unsafe {
            libc::close(self.prog_fd);
            libc::close(self.xsks_map_fd);
        }
    }
}

// ── BPF syscalls ────────────────────────────────────────────────────

fn bpf_create_xskmap(max_entries: u32) -> io::Result<i32> {
    #[repr(C)]
    struct BpfAttrMapCreate {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    }

    let attr = BpfAttrMapCreate {
        map_type: BPF_MAP_TYPE_XSKMAP,
        key_size: 4,
        value_size: 4,
        max_entries,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const _,
            std::mem::size_of::<BpfAttrMapCreate>(),
        )
    } as i32;

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn bpf_prog_load(insns: &[u8]) -> io::Result<i32> {
    let license = b"GPL\0";
    let mut log_buf = vec![0u8; 65536];

    // The kernel's bpf_attr union for BPF_PROG_LOAD is large.
    // We need at least the fields up to kern_version, padded to the
    // minimum size the kernel accepts. Using 256 bytes to be safe.
    #[repr(C)]
    struct BpfAttrProgLoad {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        _pad: [u8; 208], // Pad to 256 bytes total.
    }

    let attr = BpfAttrProgLoad {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: (insns.len() / 8) as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
        kern_version: 0,
        _pad: [0; 208],
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            &attr as *const _,
            std::mem::size_of::<BpfAttrProgLoad>(),
        )
    } as i32;

    if fd < 0 {
        let err = io::Error::last_os_error();
        let log_end = log_buf.iter().position(|&b| b == 0).unwrap_or(0);
        if log_end > 0 {
            let log_str = String::from_utf8_lossy(&log_buf[..log_end]);
            eprintln!("  BPF verifier log:\n{log_str}");
        }
        return Err(err);
    }
    Ok(fd)
}

fn bpf_map_update(map_fd: i32, key: &u32, value: &i32) -> io::Result<()> {
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let attr = BpfAttrMapElem {
        map_fd: map_fd as u32,
        key: key as *const _ as u64,
        value: value as *const _ as u64,
        flags: 0, // BPF_ANY
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr as *const _,
            std::mem::size_of::<BpfAttrMapElem>(),
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ── XDP attach/detach via netlink ───────────────────────────────────

fn attach_xdp(ifindex: u32, prog_fd: i32) -> io::Result<()> {
    // Use the SIOCETHTOOL / netlink approach, but the simplest way
    // that works on all kernels is via the if_link netlink interface.
    // For simplicity, shell out to `ip link set dev <name> xdpgeneric obj ...`
    // But we already have the fd. Use the bpf_set_link_xdp_fd equivalent.

    // Direct approach: set XDP fd via netlink RTM_SETLINK.
    // This is complex. Simpler: use the deprecated but working SIOCSIFXDP.
    // Actually simplest: use libc's if_nametoindex + raw netlink.

    // For now, use the ip command — it works and avoids 200 lines of netlink.
    let ifname = ifindex_to_name(ifindex)?;
    let fd_path = format!("/proc/self/fd/{prog_fd}");
    let output = std::process::Command::new("ip")
        .args(["link", "set", "dev", &ifname, "xdpgeneric", "pinned", &fd_path])
        .output();

    // Fallback: use the bpf netlink API via raw netlink socket.
    // If ip command doesn't support pinned fd, try bpf_xdp_attach.
    match output {
        Ok(out) if out.status.success() => Ok(()),
        _ => attach_xdp_netlink(ifindex, prog_fd),
    }
}

fn attach_xdp_netlink(ifindex: u32, prog_fd: i32) -> io::Result<()> {
    // Netlink RTM_SETLINK with IFLA_XDP attribute.
    // This is the proper way — no shelling out.
    use std::os::unix::io::FromRawFd;

    let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    // Build netlink message: RTM_SETLINK + IFLA_XDP { IFLA_XDP_FD + IFLA_XDP_FLAGS }
    const RTM_SETLINK: u16 = 19;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const IFLA_XDP: u16 = 43;
    const IFLA_XDP_FD: u16 = 1;
    const IFLA_XDP_FLAGS: u16 = 3;

    // nlmsghdr (16) + ifinfomsg (16) + IFLA_XDP nla (4) + IFLA_XDP_FD nla (8) + IFLA_XDP_FLAGS nla (8) = 52
    let mut buf = [0u8; 64];
    let mut off = 0;

    // nlmsghdr
    let total_len: u32 = 52;
    buf[off..off + 4].copy_from_slice(&total_len.to_ne_bytes());
    off += 4;
    buf[off..off + 2].copy_from_slice(&RTM_SETLINK.to_ne_bytes());
    off += 2;
    buf[off..off + 2].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    off += 2;
    off += 8; // seq + pid = 0

    // ifinfomsg
    buf[off] = libc::AF_UNSPEC as u8; // family
    off += 4; // family + pad + type
    let idx_bytes = ifindex.to_ne_bytes();
    buf[off..off + 4].copy_from_slice(&idx_bytes); // ifindex
    off += 4;
    off += 8; // flags + change

    // IFLA_XDP (nested, len = 4 + 8 + 8 = 20)
    let xdp_nla_len: u16 = 20;
    buf[off..off + 2].copy_from_slice(&xdp_nla_len.to_ne_bytes());
    off += 2;
    let xdp_type = IFLA_XDP | (1 << 15); // NLA_F_NESTED
    buf[off..off + 2].copy_from_slice(&xdp_type.to_ne_bytes());
    off += 2;

    // IFLA_XDP_FD (len=8, type=1, value=prog_fd)
    let fd_nla_len: u16 = 8;
    buf[off..off + 2].copy_from_slice(&fd_nla_len.to_ne_bytes());
    off += 2;
    buf[off..off + 2].copy_from_slice(&IFLA_XDP_FD.to_ne_bytes());
    off += 2;
    buf[off..off + 4].copy_from_slice(&prog_fd.to_ne_bytes());
    off += 4;

    // IFLA_XDP_FLAGS (len=8, type=3, value=XDP_FLAGS_SKB_MODE)
    let flags_nla_len: u16 = 8;
    buf[off..off + 2].copy_from_slice(&flags_nla_len.to_ne_bytes());
    off += 2;
    buf[off..off + 2].copy_from_slice(&IFLA_XDP_FLAGS.to_ne_bytes());
    off += 2;
    buf[off..off + 4].copy_from_slice(&XDP_FLAGS_SKB_MODE.to_ne_bytes());

    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;

    let ret = unsafe {
        libc::sendto(
            sock,
            buf.as_ptr() as *const _,
            total_len as usize,
            0,
            &sa as *const _ as *const _,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err);
    }

    // Read ACK.
    let mut resp = [0u8; 128];
    let n = unsafe { libc::recv(sock, resp.as_mut_ptr() as *mut _, resp.len(), 0) };
    if n < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err);
    }
    unsafe { libc::close(sock) };

    // Check for error in nlmsghdr. Need at least 20 bytes to read resp[16..20].
    if n >= 20 {
        let nlmsg_type = u16::from_ne_bytes([resp[4], resp[5]]);
        if nlmsg_type == 2 {
            // NLMSG_ERROR
            let error = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
            if error < 0 {
                return Err(io::Error::from_raw_os_error(-error));
            }
        }
    }

    Ok(())
}

fn detach_xdp(ifindex: u32) -> io::Result<()> {
    attach_xdp_netlink(ifindex, -1) // fd=-1 detaches
}

fn ifindex_to_name(ifindex: u32) -> io::Result<String> {
    let mut buf = [0u8; 16];
    let ret = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut _) };
    if ret.is_null() {
        return Err(io::Error::last_os_error());
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8(buf[..end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ifname"))
}

// ── Minimal ELF parser ──────────────────────────────────────────────

fn parse_and_patch_elf(elf: &[u8], map_fd: i32) -> io::Result<Vec<u8>> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not an ELF"));
    }

    let e_type = u16::from_le_bytes([elf[16], elf[17]]);
    let e_machine = u16::from_le_bytes([elf[18], elf[19]]);
    if e_type != ET_REL || e_machine != EM_BPF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a BPF relocatable ELF",
        ));
    }

    let e_shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes([elf[58], elf[59]]) as usize;
    let e_shnum = u16::from_le_bytes([elf[60], elf[61]]) as usize;
    let e_shstrndx = u16::from_le_bytes([elf[62], elf[63]]) as usize;

    let shstrtab_off = {
        let sh = &elf[e_shoff + e_shstrndx * e_shentsize..];
        u64::from_le_bytes(sh[24..32].try_into().unwrap()) as usize
    };

    // Collect section info.
    struct Section {
        name: String,
        sh_type: u32,
        offset: usize,
        size: usize,
        info: u32, // sh_info — for REL sections, points to the target section.
    }

    let mut sections = Vec::new();
    for i in 0..e_shnum {
        let sh = &elf[e_shoff + i * e_shentsize..];
        let sh_name_off = u32::from_le_bytes(sh[0..4].try_into().unwrap()) as usize;
        let sh_type = u32::from_le_bytes(sh[4..8].try_into().unwrap());
        let sh_offset = u64::from_le_bytes(sh[24..32].try_into().unwrap()) as usize;
        let sh_size = u64::from_le_bytes(sh[32..40].try_into().unwrap()) as usize;
        let sh_info = u32::from_le_bytes(sh[28..32].try_into().unwrap());
        // Wait, sh_info is at offset 44 in Elf64_Shdr. Let me recalculate.
        // Elf64_Shdr: name(4) type(4) flags(8) addr(8) offset(8) size(8) link(4) info(4) addralign(8) entsize(8)
        let sh_info = u32::from_le_bytes(sh[44..48].try_into().unwrap());

        let name_start = shstrtab_off + sh_name_off;
        let name_end = elf[name_start..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0)
            + name_start;
        let name = std::str::from_utf8(&elf[name_start..name_end])
            .unwrap_or("")
            .to_string();

        sections.push(Section {
            name,
            sh_type,
            offset: sh_offset,
            size: sh_size,
            info: sh_info,
        });
    }

    // Find the "xdp" program section.
    let prog_idx = sections
        .iter()
        .position(|s| s.name == "xdp" && s.sh_type == SHT_PROGBITS)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no 'xdp' section")
        })?;
    let prog = &sections[prog_idx];
    let mut insns = elf[prog.offset..prog.offset + prog.size].to_vec();

    // Find relocation sections targeting the program section.
    // These tell us which LD_IMM64 instructions reference maps.
    for sec in &sections {
        if sec.sh_type != SHT_REL {
            continue;
        }
        if sec.info as usize != prog_idx {
            continue; // This relocation targets a different section.
        }

        // Process each relocation entry (Elf64_Rel: offset(8) + info(8) = 16 bytes).
        let rel_data = &elf[sec.offset..sec.offset + sec.size];
        let mut off = 0;
        while off + 16 <= rel_data.len() {
            let r_offset = u64::from_le_bytes(rel_data[off..off + 8].try_into().unwrap()) as usize;
            // r_info contains symbol index in upper 32 bits, type in lower 32.
            // For BPF map refs, the type is R_BPF_64_64 (1).

            // At r_offset in the instruction stream, set src_reg=1 (BPF_PSEUDO_MAP_FD)
            // and imm=map_fd.
            if r_offset + 16 <= insns.len() && insns[r_offset] == 0x18 {
                // Set src_reg to BPF_PSEUDO_MAP_FD (1).
                insns[r_offset + 1] = (insns[r_offset + 1] & 0x0f) | (1 << 4);
                // Set imm to map fd.
                insns[r_offset + 4..r_offset + 8]
                    .copy_from_slice(&(map_fd as u32).to_le_bytes());
                // Zero upper 32 bits of the 64-bit immediate.
                insns[r_offset + 12..r_offset + 16].copy_from_slice(&0u32.to_le_bytes());
            }

            off += 16;
        }
    }

    Ok(insns)
}
