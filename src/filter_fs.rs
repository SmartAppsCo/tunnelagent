use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow,
};
use ignore::gitignore::Gitignore;
use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const FUSE_ROOT_ID: u64 = 1;

struct InodeData {
    real_path: PathBuf,
    rel_path: PathBuf,
}

pub struct FilterFs {
    source: PathBuf,
    matcher: Gitignore,
    next_inode: AtomicU64,
    inodes: HashMap<u64, InodeData>,
    path_to_inode: HashMap<PathBuf, u64>,
}

fn file_type_from_mode(mode: u32) -> FileType {
    let fmt = mode & libc::S_IFMT as u32;
    if fmt == libc::S_IFDIR as u32 {
        FileType::Directory
    } else if fmt == libc::S_IFLNK as u32 {
        FileType::Symlink
    } else if fmt == libc::S_IFBLK as u32 {
        FileType::BlockDevice
    } else if fmt == libc::S_IFCHR as u32 {
        FileType::CharDevice
    } else if fmt == libc::S_IFIFO as u32 {
        FileType::NamedPipe
    } else {
        FileType::RegularFile
    }
}

fn metadata_to_attr(md: &std::fs::Metadata, ino: u64) -> FileAttr {
    FileAttr {
        ino,
        size: md.size(),
        blocks: md.blocks(),
        atime: UNIX_EPOCH + Duration::new(md.atime() as u64, md.atime_nsec() as u32),
        mtime: UNIX_EPOCH + Duration::new(md.mtime() as u64, md.mtime_nsec() as u32),
        ctime: UNIX_EPOCH + Duration::new(md.ctime() as u64, md.ctime_nsec() as u32),
        crtime: UNIX_EPOCH,
        kind: file_type_from_mode(md.mode()),
        perm: (md.mode() & 0o7777) as u16,
        nlink: md.nlink() as u32,
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev() as u32,
        blksize: md.blksize() as u32,
        flags: 0,
    }
}

fn to_cstring(path: &Path) -> Option<CString> {
    CString::new(path.as_os_str().as_bytes()).ok()
}

fn io_err(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn last_os_err() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

impl FilterFs {
    pub fn new(source: PathBuf, matcher: Gitignore) -> Self {
        let mut inodes = HashMap::new();
        let mut path_to_inode = HashMap::new();
        let root_rel = PathBuf::from("");
        inodes.insert(
            FUSE_ROOT_ID,
            InodeData {
                real_path: source.clone(),
                rel_path: root_rel.clone(),
            },
        );
        path_to_inode.insert(root_rel, FUSE_ROOT_ID);
        Self {
            source,
            matcher,
            next_inode: AtomicU64::new(FUSE_ROOT_ID + 1),
            inodes,
            path_to_inode,
        }
    }

    fn is_private(&self, rel_path: &Path, is_dir: bool) -> bool {
        if rel_path.as_os_str().is_empty() {
            return false;
        }
        self.matcher
            .matched_path_or_any_parents(rel_path, is_dir)
            .is_ignore()
    }

    fn resolve(&self, ino: u64) -> Option<(&PathBuf, &PathBuf)> {
        self.inodes
            .get(&ino)
            .map(|d| (&d.real_path, &d.rel_path))
    }

    fn child_rel(&self, parent_rel: &Path, name: &OsStr) -> PathBuf {
        if parent_rel.as_os_str().is_empty() {
            PathBuf::from(name)
        } else {
            parent_rel.join(name)
        }
    }

    fn get_or_create_inode(&mut self, rel_path: PathBuf, real_path: PathBuf) -> u64 {
        if let Some(&ino) = self.path_to_inode.get(&rel_path) {
            return ino;
        }
        let ino = self.next_inode.fetch_add(1, Ordering::SeqCst);
        self.path_to_inode.insert(rel_path.clone(), ino);
        self.inodes.insert(ino, InodeData { real_path, rel_path });
        ino
    }

    fn stat(&self, path: &Path, ino: u64) -> Result<FileAttr, i32> {
        std::fs::symlink_metadata(path)
            .map(|md| metadata_to_attr(&md, ino))
            .map_err(|e| io_err(&e))
    }
}

impl Filesystem for FilterFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let (parent_real, parent_rel) = match self.resolve(parent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child_rel = self.child_rel(&parent_rel, name);
        let child_real = parent_real.join(name);
        // Private files are visible — lookup succeeds so stat/ls work
        let ino = self.get_or_create_inode(child_rel, child_real.clone());
        match self.stat(&child_real, ino) {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let real_path = match self.resolve(ino) {
            Some((r, _)) => r.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        match self.stat(&real_path, ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let (real_path, rel_path) = match self.resolve(ino) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        if self.is_private(&rel_path, real_path.is_dir()) {
            reply.error(libc::EACCES);
            return;
        }
        let c_path = match to_cstring(&real_path) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        if let Some(mode) = mode {
            if unsafe { libc::chmod(c_path.as_ptr(), mode as libc::mode_t) } < 0 {
                reply.error(last_os_err());
                return;
            }
        }
        if uid.is_some() || gid.is_some() {
            let u = uid.unwrap_or(u32::MAX);
            let g = gid.unwrap_or(u32::MAX);
            if unsafe { libc::chown(c_path.as_ptr(), u, g) } < 0 {
                reply.error(last_os_err());
                return;
            }
        }
        if let Some(size) = size {
            let ret = if let Some(fh) = fh {
                unsafe { libc::ftruncate(fh as i32, size as libc::off_t) }
            } else {
                unsafe { libc::truncate(c_path.as_ptr(), size as libc::off_t) }
            };
            if ret < 0 {
                reply.error(last_os_err());
                return;
            }
        }
        if atime.is_some() || mtime.is_some() {
            let to_ts = |t: Option<TimeOrNow>| -> libc::timespec {
                match t {
                    Some(TimeOrNow::SpecificTime(st)) => {
                        let d = st.duration_since(UNIX_EPOCH).unwrap_or_default();
                        libc::timespec {
                            tv_sec: d.as_secs() as i64,
                            tv_nsec: d.subsec_nanos() as i64,
                        }
                    }
                    Some(TimeOrNow::Now) => libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_NOW,
                    },
                    None => libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                }
            };
            let times = [to_ts(atime), to_ts(mtime)];
            if unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) } < 0 {
                reply.error(last_os_err());
                return;
            }
        }
        match self.stat(&real_path, ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let (real_path, rel_path) = match self.resolve(ino) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        if self.is_private(&rel_path, false) {
            reply.error(libc::EACCES);
            return;
        }
        match std::fs::read_link(&real_path) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(e) => reply.error(io_err(&e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let (parent_real, parent_rel) = match self.resolve(parent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child_rel = self.child_rel(&parent_rel, name);
        if self.is_private(&child_rel, true) {
            reply.error(libc::EACCES);
            return;
        }
        let child_real = parent_real.join(name);
        let c_path = match to_cstring(&child_real) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        if unsafe { libc::mkdir(c_path.as_ptr(), mode as libc::mode_t) } < 0 {
            reply.error(last_os_err());
            return;
        }
        let ino = self.get_or_create_inode(child_rel, child_real.clone());
        match self.stat(&child_real, ino) {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let (parent_real, parent_rel) = match self.resolve(parent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child_rel = self.child_rel(&parent_rel, name);
        if self.is_private(&child_rel, false) {
            reply.error(libc::EACCES);
            return;
        }
        match std::fs::remove_file(parent_real.join(name)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(io_err(&e)),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let (parent_real, parent_rel) = match self.resolve(parent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child_rel = self.child_rel(&parent_rel, name);
        if self.is_private(&child_rel, true) {
            reply.error(libc::EACCES);
            return;
        }
        match std::fs::remove_dir(parent_real.join(name)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(io_err(&e)),
        }
    }

    fn symlink(
        &mut self,
        _req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let (parent_real, parent_rel) = match self.resolve(parent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child_rel = self.child_rel(&parent_rel, link_name);
        if self.is_private(&child_rel, false) {
            reply.error(libc::EACCES);
            return;
        }
        let link_real = parent_real.join(link_name);
        match std::os::unix::fs::symlink(target, &link_real) {
            Ok(()) => {
                let ino = self.get_or_create_inode(child_rel, link_real.clone());
                match self.stat(&link_real, ino) {
                    Ok(attr) => reply.entry(&TTL, &attr, 0),
                    Err(e) => reply.error(e),
                }
            }
            Err(e) => reply.error(io_err(&e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (parent_real, parent_rel) = match self.resolve(parent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let (newparent_real, newparent_rel) = match self.resolve(newparent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let old_rel = self.child_rel(&parent_rel, name);
        let new_rel = self.child_rel(&newparent_rel, newname);
        if self.is_private(&old_rel, false) || self.is_private(&new_rel, false) {
            reply.error(libc::EACCES);
            return;
        }
        let old_real = parent_real.join(name);
        let new_real = newparent_real.join(newname);
        match std::fs::rename(&old_real, &new_real) {
            Ok(()) => {
                if let Some(ino) = self.path_to_inode.remove(&old_rel) {
                    self.path_to_inode.insert(new_rel.clone(), ino);
                    if let Some(data) = self.inodes.get_mut(&ino) {
                        data.real_path = new_real;
                        data.rel_path = new_rel;
                    }
                }
                reply.ok();
            }
            Err(e) => reply.error(io_err(&e)),
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let (real_path, rel_path) = match self.resolve(ino) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        if self.is_private(&rel_path, false) {
            reply.error(libc::EACCES);
            return;
        }
        let c_path = match to_cstring(&real_path) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
        if fd < 0 {
            reply.error(last_os_err());
        } else {
            reply.opened(fd as u64, 0);
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let mut buf = vec![0u8; size as usize];
        let n = unsafe {
            libc::pread(
                fh as i32,
                buf.as_mut_ptr() as *mut libc::c_void,
                size as usize,
                offset,
            )
        };
        if n < 0 {
            reply.error(last_os_err());
        } else {
            reply.data(&buf[..n as usize]);
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let n = unsafe {
            libc::pwrite(
                fh as i32,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                offset,
            )
        };
        if n < 0 {
            reply.error(last_os_err());
        } else {
            reply.written(n as u32);
        }
    }

    fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        if unsafe { libc::fsync(fh as i32) } < 0 {
            reply.error(last_os_err());
        } else {
            reply.ok();
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        unsafe { libc::close(fh as i32) };
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let ret = if datasync {
            unsafe { libc::fdatasync(fh as i32) }
        } else {
            unsafe { libc::fsync(fh as i32) }
        };
        if ret < 0 {
            reply.error(last_os_err());
        } else {
            reply.ok();
        }
    }

    fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        let rel_path = match self.resolve(ino) {
            Some((_, p)) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        if self.is_private(&rel_path, true) {
            reply.error(libc::EACCES);
            return;
        }
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let (real_path, rel_path) = match self.resolve(ino) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (ino, FileType::Directory, "..".to_string()),
        ];

        match std::fs::read_dir(&real_path) {
            Ok(read_dir) => {
                for entry in read_dir.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let child_rel = self.child_rel(&rel_path, &entry.file_name());
                    // Private entries are visible in listings — access is blocked at open/opendir
                    let child_real = real_path.join(&name);
                    let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                    let child_ino = self.get_or_create_inode(child_rel, child_real);
                    let ft = if is_dir {
                        FileType::Directory
                    } else if entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false) {
                        FileType::Symlink
                    } else {
                        FileType::RegularFile
                    };
                    entries.push((child_ino, ft, name));
                }
            }
            Err(e) => {
                reply.error(io_err(&e));
                return;
            }
        }

        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let c_path = match to_cstring(&self.source) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) < 0 {
                reply.error(last_os_err());
            } else {
                reply.statfs(
                    stat.f_blocks,
                    stat.f_bfree,
                    stat.f_bavail,
                    stat.f_files,
                    stat.f_ffree,
                    stat.f_bsize as u32,
                    stat.f_namemax as u32,
                    stat.f_frsize as u32,
                );
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let (parent_real, parent_rel) = match self.resolve(parent) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child_rel = self.child_rel(&parent_rel, name);
        if self.is_private(&child_rel, false) {
            reply.error(libc::EACCES);
            return;
        }
        let child_real = parent_real.join(name);
        let c_path = match to_cstring(&child_real) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        let fd = unsafe { libc::open(c_path.as_ptr(), flags | libc::O_CREAT, mode) };
        if fd < 0 {
            reply.error(last_os_err());
            return;
        }
        let ino = self.get_or_create_inode(child_rel, child_real.clone());
        match self.stat(&child_real, ino) {
            Ok(attr) => reply.created(&TTL, &attr, 0, fd as u64, 0),
            Err(e) => {
                unsafe { libc::close(fd) };
                reply.error(e);
            }
        }
    }

    fn access(&mut self, _req: &Request, ino: u64, mask: i32, reply: ReplyEmpty) {
        let (real_path, _rel_path) = match self.resolve(ino) {
            Some((r, p)) => (r.clone(), p.clone()),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let c_path = match to_cstring(&real_path) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        if unsafe { libc::access(c_path.as_ptr(), mask) } < 0 {
            reply.error(last_os_err());
        } else {
            reply.ok();
        }
    }
}

/// Mount a filtering FUSE passthrough filesystem.
/// Returns a BackgroundSession that keeps the mount alive until dropped.
pub fn mount_filter(
    source: PathBuf,
    mount_point: &str,
    matcher: Gitignore,
) -> anyhow::Result<fuser::BackgroundSession> {
    let fs = FilterFs::new(source, matcher);
    let options = vec![
        MountOption::FSName("agent-tunnel".to_string()),
        MountOption::DefaultPermissions,
    ];
    let session = fuser::spawn_mount2(fs, mount_point, &options)?;
    Ok(session)
}
