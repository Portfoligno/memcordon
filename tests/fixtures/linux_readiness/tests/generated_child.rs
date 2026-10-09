use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};

fn identity(pid: u32) -> (u32, u64) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields = stat.rsplit_once(')').unwrap().1.split_whitespace().collect::<Vec<_>>();
    (fields[1].parse().unwrap(), fields[19].parse().unwrap())
}

fn json_text(value: &str) -> String {
    let mut result = String::from("\"");
    for c in value.chars() {
        match c { '\"' => result.push_str("\\\""), '\\' => result.push_str("\\\\"),
            c if c.is_control() => result.push_str(&format!("\\u{:04x}",c as u32)), c => result.push(c) }
    }
    result.push('\"'); result
}

fn persist(path: &std::path::Path, bytes: &[u8]) {
    let mut file=std::fs::OpenOptions::new().write(true).create_new(true)
        .custom_flags(0o400000 | 0o2000000).open(path).unwrap();
    file.write_all(bytes).unwrap();file.sync_all().unwrap();
    std::fs::File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
}

fn with_created_child(mut child:Child,operation:impl FnOnce(&mut Child)) {
    let original=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||operation(&mut child)));
    let mut failures=Vec::new();
    match child.try_wait() {
        Ok(Some(_))=>{},
        Ok(None)=>if let Err(error)=child.kill(){failures.push(format!("signal: {error}"));},
        Err(error)=>{failures.push(format!("observe: {error}"));if let Err(error)=child.kill(){failures.push(format!("signal: {error}"));}},
    }
    child.stdin.take();if let Err(error)=child.wait(){failures.push(format!("reap: {error}"));}
    if !failures.is_empty(){eprintln!("exact generated child cleanup unresolved: {}",failures.join("; "));}
    if let Err(original)=original{std::panic::resume_unwind(original);}
    assert!(failures.is_empty(),"generated child native cleanup unresolved");
}

#[test]
fn compiled_child_writes_exact_binary_artifact() {
    let directory=std::env::temp_dir();
    let output=directory.join("generated-readiness-artifact.bin");
    let challenge=std::fs::read_to_string(directory.join("generated-child-challenge.txt")).unwrap();
    assert!(challenge.len()==64&&challenge.bytes().all(|byte|byte.is_ascii_hexdigit()));
    let source=std::fs::OpenOptions::new().read(true).custom_flags(0o400000 | 0o2000000)
        .open(env!("CARGO_BIN_EXE_owned-readiness-child")).unwrap();
    let source_before=source.metadata().unwrap();assert!(source_before.is_file());
    let mut image_bytes=Vec::new();(&source).take(16*1024*1024+1).read_to_end(&mut image_bytes).unwrap();
    let source_after=source.metadata().unwrap();
    assert!(image_bytes.len()<=16*1024*1024);
    assert_eq!((source_before.dev(),source_before.ino(),source_before.len(),source_before.ctime(),source_before.ctime_nsec()),
        (source_after.dev(),source_after.ino(),source_after.len(),source_after.ctime(),source_after.ctime_nsec()));
    assert_eq!(image_bytes.len() as u64,source_before.len());
    let program=directory.join("generated-child-executable.bin");
    let mut copied=std::fs::OpenOptions::new().write(true).create_new(true).custom_flags(0o400000|0o2000000).open(&program).unwrap();
    copied.write_all(&image_bytes).unwrap();copied.set_permissions(std::fs::Permissions::from_mode(0o755)).unwrap();copied.sync_all().unwrap();drop(copied);
    std::fs::File::open(&directory).unwrap().sync_all().unwrap();
    let image=std::fs::OpenOptions::new().read(true).custom_flags(0o400000 | 0o2000000).open(&program).unwrap();
    let image_metadata=image.metadata().unwrap();assert!(image_metadata.is_file()&&image_metadata.nlink()==1);
    let child=Command::new(&program).arg(&output).env_clear()
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    with_created_child(child,|child|{
    let mut ready=[0];child.stdout.as_mut().unwrap().read_exact(&mut ready).unwrap();assert_eq!(ready,[0xA5]);
    let pid=child.id();let (parent,birth)=identity(pid);
    let parent_pid=std::process::id();let (compiler_pid,parent_birth)=identity(parent_pid);
    let (_,compiler_birth)=identity(compiler_pid);
    assert_eq!(parent,parent_pid);assert!(compiler_birth<=parent_birth&&parent_birth<=birth);
    let running=std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
    assert_eq!((running.dev(),running.ino()),(image_metadata.dev(),image_metadata.ino()));
    let mut observed_image=Vec::new();(&image).take(16*1024*1024+1).read_to_end(&mut observed_image).unwrap();assert_eq!(observed_image,image_bytes);
    let created=format!("{{\"format\":\"memcordon.linux-generated-child-created\",\"revision\":1,\"challenge\":{},\"pid\":{pid},\"birth\":{birth},\"parent_pid\":{parent_pid},\"parent_birth\":{parent_birth},\"compiler_pid\":{compiler_pid},\"compiler_birth\":{compiler_birth},\"image_device\":{},\"image_inode\":{},\"program\":{},\"output\":{},\"creation_owner_retained\":true,\"ready_before_release\":true}}",
        json_text(&challenge),image_metadata.dev(),image_metadata.ino(),json_text(program.to_str().unwrap()),json_text(output.to_str().unwrap()));
    persist(&directory.join("generated-child-created.json"),created.as_bytes());
    println!("MEMCORDON-GENERATED-CHILD-HELD {created}");std::io::stdout().flush().unwrap();
    let gate=directory.join("generated-child-controller-release");
    loop {
        match std::fs::OpenOptions::new().read(true).custom_flags(0o400000 | 0o2000000).open(&gate) {
            Ok(file)=>{let mut bytes=Vec::new();file.take(2).read_to_end(&mut bytes).unwrap();assert_eq!(bytes,b"R");break;},
            Err(error)if error.kind()==std::io::ErrorKind::NotFound=>std::thread::sleep(std::time::Duration::from_millis(2)),
            Err(error)=>panic!("generated controller gate: {error}"),
        }
    }
    child.stdin.as_mut().unwrap().write_all(b"R").unwrap();child.stdin.take();
    let status=child.wait().unwrap();assert!(status.success());
    let retired=format!("{{\"format\":\"memcordon.linux-generated-child-retired\",\"revision\":1,\"challenge\":{},\"pid\":{pid},\"birth\":{birth},\"parent_pid\":{parent_pid},\"parent_birth\":{parent_birth},\"native_wait_status\":{},\"same_creation_owner_waited\":true}}",json_text(&challenge),status.into_raw());
    persist(&directory.join("generated-child-retired.json"),retired.as_bytes());
    assert_eq!(std::fs::read(&output).unwrap(),(u8::MIN..=u8::MAX).collect::<Vec<_>>());
    });
}
