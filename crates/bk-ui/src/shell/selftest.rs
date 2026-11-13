//! A scripted check of native windows in the real application.
//!
//! Headless tests cannot open operating-system windows (egui embeds
//! viewports there), so this mode drives the real binary: with
//! `BASILISK_UI_SELF_TEST=run` and `BASILISK_UI_SELF_TEST_DIR=<folder>`
//! it detaches the Decompiler into a native window, checks that window
//! paints and follows navigation done in the main window, waits for the
//! Go To key typed into the detached window (sent by a script), docks it
//! back, closes a detached window through the window system, detaches
//! again and quits so the layout is saved. `restore` then checks that the
//! detached window comes back. Settings are kept in the given folder, never
//! in the user's own; the outcome is written to `report.txt` there.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::layout::Place;
use super::overlay::Overlay;
use super::tool::Tool;
use crate::model::Location;
use crate::views::ViewKind;

/// Which script to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// Detach, follow, keys, dock, close, detach and quit.
    Run,
    /// Check that the saved detached window came back.
    Restore,
}

/// What detached windows report back to the script.
#[derive(Debug, Default)]
pub struct Probe {
    /// Frames painted by detached windows.
    pub painted: AtomicU64,
    /// Tab titles the detached windows drew last.
    pub titles: Mutex<Vec<String>>,
    /// Put a G key press into the next detached frame's input (when no
    /// script can type: macOS needs Accessibility permission for that).
    pub inject_g: std::sync::atomic::AtomicBool,
}

/// The script's state.
#[derive(Debug)]
pub struct SelfTest {
    script: Script,
    dir: PathBuf,
    step: usize,
    since: Instant,
    mark: u64,
    window: Option<u64>,
    log: Vec<String>,
    failed: bool,
    injected: bool,
    /// Shared with the detached windows.
    pub probe: Arc<Probe>,
}

const TIMEOUT: Duration = Duration::from_secs(20);

impl SelfTest {
    /// The script named by the environment, if any.
    pub fn from_env() -> Option<Self> {
        let script = match std::env::var("BASILISK_UI_SELF_TEST").ok()?.as_str() {
            "run" => Script::Run,
            "restore" => Script::Restore,
            _ => return None,
        };
        let dir = PathBuf::from(std::env::var_os("BASILISK_UI_SELF_TEST_DIR")?);
        Some(Self {
            script,
            dir,
            step: 0,
            since: Instant::now(),
            mark: 0,
            window: None,
            log: Vec::new(),
            failed: false,
            injected: false,
            probe: Arc::new(Probe::default()),
        })
    }

    /// Where eframe keeps settings during the test.
    pub fn settings_dir(&self) -> PathBuf {
        self.dir.join("settings")
    }

    fn note(&mut self, ok: bool, what: impl Into<String>) {
        let what = what.into();
        tracing::info!("self-test: {} {what}", if ok { "ok" } else { "FAIL" });
        self.log
            .push(format!("{} {what}", if ok { "ok  " } else { "FAIL" }));
        if !ok {
            self.failed = true;
        }
    }

    fn next(&mut self) {
        self.step += 1;
        self.since = Instant::now();
    }

    fn timed_out(&mut self, what: &str) -> bool {
        if self.since.elapsed() > TIMEOUT {
            self.note(false, format!("timed out: {what}"));
            self.step = usize::MAX - 1;
            return true;
        }
        false
    }

    fn finish(&mut self, ctx: &egui::Context) {
        let verdict = if self.failed { "FAIL" } else { "PASS" };
        self.log.push(verdict.to_owned());
        let path = self.dir.join(match self.script {
            Script::Run => "report-run.txt",
            Script::Restore => "report-restore.txt",
        });
        if let Err(e) = std::fs::write(&path, self.log.join("\n") + "\n") {
            tracing::error!("self-test: cannot write {}: {e}", path.display());
        }
        ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Close);
        self.step = usize::MAX;
    }

    fn painted(&self) -> u64 {
        self.probe.painted.load(Ordering::Relaxed)
    }

    fn title_has(&self, s: &str) -> bool {
        self.probe.titles.lock().iter().any(|t| t.contains(s))
    }

    /// Advances the script; called once per main-window frame.
    pub fn tick(&mut self, ctx: &egui::Context, tool: &mut Tool) {
        ctx.request_repaint_after(Duration::from_millis(50));
        if self.step == usize::MAX {
            return;
        }
        if self.step == usize::MAX - 1 {
            self.finish(ctx);
            return;
        }
        let Some(ws) = tool.ws.as_mut() else {
            self.note(false, "no program open");
            self.finish(ctx);
            return;
        };
        let embedded = ctx.embed_viewports();
        match (self.script, self.step) {
            (Script::Run, 0) => {
                if self.since.elapsed() > Duration::from_secs(1) {
                    let dec = ws.layout.find_kind(ViewKind::Decompiler);
                    self.window = dec.and_then(|d| ws.layout.detach(d));
                    self.note(
                        self.window.is_some(),
                        "Detach Window moved the Decompiler out of the main window",
                    );
                    self.mark = self.painted();
                    self.next();
                }
            }
            (Script::Run, 1) => {
                if self.painted() > self.mark + 2 {
                    self.note(!embedded, format!("the detached window is a native window (embedded: {embedded}) and paints"));
                    self.mark = self.painted();
                    let target = crate::demo::DemoProgram::licd()
                        .ok()
                        .and_then(|p| {
                            use crate::model::ProgramSource as _;
                            p.lookup("rc4_init", 5).ok()
                        })
                        .and_then(|v| v.into_iter().find(|s| &*s.name == "rc4_init"));
                    if let Some(s) = target {
                        ws.shared.nav.go(Location::at(s.address));
                    }
                    self.next();
                } else {
                    self.timed_out("detached window painting");
                }
            }
            (Script::Run, 2) => {
                if self.title_has("Decompile: rc4_init") {
                    self.note(
                        true,
                        "the detached Decompiler followed navigation done in the main window",
                    );
                    if let Some(w) = self.window {
                        let vp = super::app::viewport_id(w);
                        ctx.send_viewport_cmd_to(vp, egui::ViewportCommand::Focus);
                    }
                    let _ = std::fs::write(self.dir.join("ready-for-keys"), "");
                    self.next();
                } else {
                    self.timed_out("detached window following navigation");
                }
            }
            (Script::Run, 3) => {
                let vp = self.window.map(super::app::viewport_id);
                let opened =
                    matches!(&ws.overlay, Some((at, Overlay::Palette(_))) if Some(*at) == vp);
                // Activating the app makes the main window key; keep asking
                // the window system to focus the detached one.
                if let Some(v) = vp
                    && self.since.elapsed().as_millis() % 1000 < 60
                {
                    ctx.send_viewport_cmd_to(v, egui::ViewportCommand::Focus);
                }
                if matches!(&ws.overlay, Some((at, Overlay::Palette(_))) if *at == egui::ViewportId::ROOT)
                {
                    self.log.push("note G arrived in the main window (it had the keyboard); focusing the detached window again".to_owned());
                    ws.overlay = None;
                }
                if !opened && self.since.elapsed() > Duration::from_secs(6) && !self.injected {
                    self.injected = true;
                    self.probe.inject_g.store(true, Ordering::Relaxed);
                    self.log.push("note no OS key arrived (no permission to send keystrokes?); placing a G press into the detached window's own input".to_owned());
                }
                if opened {
                    self.note(
                        true,
                        if self.injected {
                            "a G press in the detached window's input opened Go To in that window (key routing; OS key delivery not verified here)"
                        } else {
                            "G typed into the detached window opened Go To in that window"
                        },
                    );
                    ws.overlay = None;
                    let _ = std::fs::remove_file(self.dir.join("ready-for-keys"));
                    self.next();
                } else if self.since.elapsed() > Duration::from_secs(15) {
                    let _ = std::fs::remove_file(self.dir.join("ready-for-keys"));
                    self.note(
                        false,
                        "no G key arrived in the detached window (is the key script running?)",
                    );
                    self.next();
                }
            }
            (Script::Run, 4) => {
                if let Some(w) = self.window {
                    ws.layout.dock(w);
                }
                let back = ws
                    .layout
                    .find_kind(ViewKind::Decompiler)
                    .and_then(|d| ws.layout.window_of(d));
                self.note(
                    ws.layout.windows.is_empty() && back == Some(Place::Main),
                    "Dock Window put the Decompiler back in the main window",
                );
                let strings = ws.layout.find_kind(ViewKind::Strings);
                self.window = strings.and_then(|s| ws.layout.detach(s));
                self.mark = self.painted();
                self.next();
            }
            (Script::Run, 5) => {
                if self.painted() > self.mark + 2 {
                    if let Some(w) = self.window {
                        ctx.send_viewport_cmd_to(
                            super::app::viewport_id(w),
                            egui::ViewportCommand::Close,
                        );
                    }
                    self.next();
                } else {
                    self.timed_out("second detached window painting");
                }
            }
            (Script::Run, 6) => {
                if ws.layout.windows.is_empty() {
                    self.note(ws.layout.find_kind(ViewKind::Strings).is_none(), "closing a detached window through the window system closed its pane, not the tool");
                    let dec = ws.layout.find_kind(ViewKind::Decompiler);
                    self.window = dec.and_then(|d| ws.layout.detach(d));
                    self.mark = self.painted();
                    self.next();
                } else {
                    self.timed_out("detached window closing");
                }
            }
            (Script::Run, 7) => {
                let placed = ws
                    .layout
                    .windows
                    .first()
                    .is_some_and(|w| w.position.is_some() && w.size.is_some());
                if self.painted() > self.mark + 2 && placed {
                    let w = ws.layout.windows.first().map(|w| (w.position, w.size));
                    self.note(
                        true,
                        format!(
                            "detached the Decompiler again at {w:?}; quitting to save the layout"
                        ),
                    );
                    let _ = std::fs::write(self.dir.join("expected-window.txt"), format!("{w:?}"));
                    self.step = usize::MAX - 1;
                } else {
                    self.timed_out("third detached window placing itself");
                }
            }
            (Script::Restore, 0) => {
                let restored = ws
                    .layout
                    .windows
                    .first()
                    .map(|w| (w.position, w.size, w.tabs().next().map(|t| t.kind)));
                if self.painted() > 2 {
                    let expected = std::fs::read_to_string(self.dir.join("expected-window.txt"))
                        .unwrap_or_default();
                    let ok = restored
                        .as_ref()
                        .is_some_and(|r| r.2 == Some(ViewKind::Decompiler));
                    self.note(ok && !embedded, format!("the saved detached window came back as a native window: {restored:?} (saved {expected})"));
                    self.step = usize::MAX - 1;
                } else {
                    self.timed_out("restored window painting");
                }
            }
            _ => self.step = usize::MAX - 1,
        }
    }
}
