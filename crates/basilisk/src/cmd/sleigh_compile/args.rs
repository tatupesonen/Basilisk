//! The command line of `basilisk sleigh compile`: Ghidra's C++ options and
//! Java's additions (`SleighCompileOptions.java`), with Java's file-name
//! rules (extensions tested at the end of the name, ignoring case).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use bk_sleigh_compiler::Options;
use bk_sleigh_syntax::Defines;

/// What to compile.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Job {
    /// One specification into one file.
    One {
        /// The `.slaspec`.
        input: PathBuf,
        /// The output file.
        output: PathBuf,
    },
    /// Every `.slaspec` under a directory, each beside itself.
    All(PathBuf),
}

/// A parsed command line.
#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) job: Job,
    pub(crate) defines: Defines,
    pub(crate) options: Options,
    /// `-y`: write the XML form.
    pub(crate) xml: bool,
}

/// Why the command line was refused: the message for standard error.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused(pub(crate) String);

fn refuse<T>(message: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(message.into()))
}

/// Whether the file name of `path` ends with `ext` (with its dot), ignoring
/// ASCII case.
pub(crate) fn has_extension(path: &Path, ext: &str) -> bool {
    path.file_name()
        .map(OsStr::to_string_lossy)
        .is_some_and(|name| {
            name.len() >= ext.len()
                && name
                    .get(name.len() - ext.len()..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(ext))
        })
}

/// `path` with `ext` appended to its file name.
pub(crate) fn with_appended(path: &Path, ext: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

/// The options read from an options file: one per line, trimmed, blank
/// lines and `#` comments skipped (`getOptionsFromFile`).
fn options_file(path: &Path) -> Result<Vec<OsString>, Refused> {
    if !path.is_file() {
        return refuse(format!("Options file not found: {}", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        Refused(format!(
            "Reading options file failed ({}): {e}",
            path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned())
        ))
    })?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(OsString::from)
        .collect())
}

/// Where module `name` lives under the specification root (`-d`): the
/// first of `Ghidra/*/<name>` in sorted order that is a directory.
fn module_dir(root: Option<&Path>, name: &str) -> Option<PathBuf> {
    let root = root?;
    let direct = root.join(name);
    let mut groups: Vec<PathBuf> = std::fs::read_dir(root.join("Ghidra"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    groups.sort();
    groups
        .into_iter()
        .map(|g| g.join(name))
        .find(|p| p.is_dir())
        .or_else(|| direct.is_dir().then_some(direct))
}

/// Parses the arguments after `sleigh compile`. `root` is the
/// specification root `-d` resolves modules under.
pub(crate) fn parse(args: &[OsString], root: Option<&Path>) -> Result<Args, Refused> {
    let mut rest: std::collections::VecDeque<OsString> = args.iter().cloned().collect();
    let mut defines = Defines::new();
    let mut switches: Vec<String> = Vec::new();
    let mut xml = false;
    let mut all: Option<Option<PathBuf>> = None;
    while let Some(arg) = rest.front() {
        let text = arg.to_string_lossy().into_owned();
        if !text.starts_with('-') {
            break;
        }
        rest.pop_front();
        if text.trim().is_empty() {
            continue;
        }
        let mut chars = text.chars().skip(1);
        match chars.next() {
            Some('i') => {
                let Some(file) = rest.pop_front() else {
                    return refuse("Missing options input file name");
                };
                let mut injected: std::collections::VecDeque<OsString> =
                    options_file(Path::new(&file))?.into();
                injected.extend(rest.drain(..));
                rest = injected;
            }
            Some('D') => {
                let body: String = chars.collect();
                let Some((name, value)) = body.split_once('=') else {
                    return refuse(format!("Bad sleigh option: {text}"));
                };
                defines.set(name, value);
            }
            Some('d') => {
                let name: String = chars.collect();
                let Some(dir) = module_dir(root, &name) else {
                    return refuse(format!("Failed to resolve module reference: {text}"));
                };
                defines.set(name, dir.to_string_lossy().into_owned());
            }
            Some('a') => {
                // Java's form takes the directory as the next argument; the
                // C++ form takes it from the trailing name (default `.`).
                let next_is_dir = rest
                    .front()
                    .is_some_and(|n| !n.to_string_lossy().starts_with('-'));
                all = Some(if next_is_dir {
                    rest.pop_front().map(PathBuf::from)
                } else {
                    None
                });
            }
            Some('u' | 'l' | 'c' | 'n' | 't' | 'e' | 's' | 'f') => switches.push(text),
            Some('y') => xml = true,
            Some('x') => {}
            _ => return refuse(format!("Unknown option: {text}")),
        }
    }
    let options = Options::from_switches(switches.iter().map(String::as_str));
    let job = match all {
        Some(dir) => {
            let dir = match dir {
                Some(d) => d,
                None => rest.pop_front().map_or_else(|| PathBuf::from("."), PathBuf::from),
            };
            if !rest.is_empty() {
                return refuse("Too many parameters");
            }
            if !dir.is_dir() {
                return refuse(format!("{} is not a directory", dir.display()));
            }
            Job::All(dir)
        }
        None => {
            let Some(input) = rest.pop_front() else {
                return refuse("Missing input file name");
            };
            let output = rest.pop_front();
            if !rest.is_empty() {
                return refuse("Too many parameters");
            }
            let input = PathBuf::from(input);
            let (input, base) = if has_extension(&input, ".slaspec") {
                let base = input.with_extension("");
                (input, base)
            } else {
                (with_appended(&input, ".slaspec"), input)
            };
            let output = match output.map(PathBuf::from) {
                Some(o) if has_extension(&o, ".sla") => o,
                Some(o) => with_appended(&o, ".sla"),
                None => with_appended(&base, ".sla"),
            };
            Job::One { input, output }
        }
    };
    Ok(Args {
        job,
        defines,
        options,
        xml,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn one(list: &[&str]) -> (PathBuf, PathBuf) {
        match parse(&args(list), None).unwrap().job {
            Job::One { input, output } => (input, output),
            Job::All(_) => panic!("not one"),
        }
    }

    #[test]
    fn file_names_follow_java() {
        let p = |s: &str| PathBuf::from(s);
        assert_eq!(one(&["in.slaspec"]), (p("in.slaspec"), p("in.sla")));
        assert_eq!(one(&["in"]), (p("in.slaspec"), p("in.sla")));
        assert_eq!(one(&["IN.SLASPEC"]), (p("IN.SLASPEC"), p("IN.sla")));
        assert_eq!(one(&["in.slaspec", "out"]), (p("in.slaspec"), p("out.sla")));
        assert_eq!(one(&["in.slaspec", "out.SLA"]), (p("in.slaspec"), p("out.SLA")));
        // The extension must be at the end (C++ looks anywhere in the name).
        assert_eq!(
            one(&["a.slaspec.bak"]),
            (p("a.slaspec.bak.slaspec"), p("a.slaspec.bak.sla"))
        );
        assert_eq!(one(&["in", "x.sla.old"]).1, p("x.sla.old.sla"));
    }

    #[test]
    fn refusals() {
        let refused = |list: &[&str]| parse(&args(list), None).unwrap_err().0;
        assert_eq!(refused(&[]), "Missing input file name");
        assert_eq!(refused(&["-q", "x"]), "Unknown option: -q");
        assert_eq!(refused(&["-DNAME", "x"]), "Bad sleigh option: -DNAME");
        assert_eq!(refused(&["a", "b", "c"]), "Too many parameters");
        assert_eq!(refused(&["-i"]), "Missing options input file name");
        assert!(refused(&["-dNoSuchModule", "x"]).starts_with("Failed to resolve module"));
    }

    #[test]
    fn switches_and_defines() {
        let a = parse(&args(&["-l", "-u", "-y", "-x", "-DA=1=2", "in"]), None).unwrap();
        assert!(!a.options.lenient_conflicts);
        assert!(a.options.warn_unnecessary_pcode);
        assert!(a.xml);
        assert_eq!(a.defines.get("A"), Some("1=2"));
    }

    /// Ghidra's `SleighCompileOptionsTest`.
    mod sleigh_compile_options_test {
        use super::*;

        fn temp_file(dir: &Path, text: &str) -> OsString {
            let path = dir.join("sleigh_args");
            std::fs::write(&path, text).unwrap();
            path.into_os_string()
        }

        #[test]
        fn arg_file() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("root");
            std::fs::create_dir_all(root.join("Ghidra").join("Processors").join("x86")).unwrap();
            let file = temp_file(
                dir.path(),
                "-x\n-u\n-l\n-n\n-t\n-e\n-c\n-f\n-s\n-DTESTNAME=TESTVALUE\n-dx86\n",
            );
            let defaults = Options::default();
            let a = parse(&[OsString::from("-i"), file, OsString::from("in")], Some(&root)).unwrap();
            let o = a.options;
            assert!(o.warn_unnecessary_pcode && !defaults.warn_unnecessary_pcode);
            assert!(!o.lenient_conflicts && defaults.lenient_conflicts);
            assert!(o.warn_all_nops && !defaults.warn_all_nops);
            assert!(o.warn_dead_temps && !defaults.warn_dead_temps);
            assert!(o.enforce_local_key && !defaults.enforce_local_key);
            assert!(o.warn_all_collisions && !defaults.warn_all_collisions);
            assert!(o.warn_unused_fields && !defaults.warn_unused_fields);
            assert!(!o.case_insensitive_duplicates && defaults.case_insensitive_duplicates);
            assert_eq!(a.defines.get("TESTNAME"), Some("TESTVALUE"));
            assert!(Path::new(a.defines.get("x86").unwrap()).is_dir());
        }

        fn names(job: &Job) -> (String, String) {
            match job {
                Job::One { input, output } => (
                    input.file_name().unwrap().to_string_lossy().into_owned(),
                    output.file_name().unwrap().to_string_lossy().into_owned(),
                ),
                Job::All(_) => panic!("not one"),
            }
        }

        fn with_file(rest: &[&str]) -> (Args, tempfile::TempDir) {
            let dir = tempfile::tempdir().unwrap();
            let file = temp_file(dir.path(), "-DTESTNAME=TESTVALUE");
            let mut list = vec![OsString::from("-i"), file];
            list.extend(rest.iter().map(OsString::from));
            (parse(&list, None).unwrap(), dir)
        }

        #[test]
        fn one_input() {
            let (a, _d) = with_file(&["inputfile.slaspec"]);
            assert_eq!(a.defines.get("TESTNAME"), Some("TESTVALUE"));
            assert_eq!(names(&a.job), ("inputfile.slaspec".into(), "inputfile.sla".into()));
        }

        #[test]
        fn one_input_default_extension() {
            let (a, _d) = with_file(&["inputfile"]);
            assert_eq!(names(&a.job), ("inputfile.slaspec".into(), "inputfile.sla".into()));
        }

        #[test]
        fn input_and_output() {
            let (a, _d) = with_file(&["inputfile.slaspec", "outputfile.sla"]);
            assert_eq!(names(&a.job), ("inputfile.slaspec".into(), "outputfile.sla".into()));
        }

        #[test]
        fn all() {
            let all = tempfile::tempdir().unwrap();
            let (a, _d) = with_file(&["-a", all.path().to_str().unwrap()]);
            assert_eq!(a.defines.get("TESTNAME"), Some("TESTVALUE"));
            assert_eq!(a.job, Job::All(all.path().to_path_buf()));
        }
    }
}
