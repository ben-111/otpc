use crate::{
    credentials_from_screenshot, credentials_from_source, expand_home, write_config, Config,
    Credential,
};
use anyhow::{Context, Result};
use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::style::{Attribute, Print, SetAttribute};
use crossterm::terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, queue};
use keyring::Entry;
use std::fs;
use std::io::{self, Stdout, Write};
use std::path::Path;
use std::time::Duration;
use totp_rs::Totp;
use tui_input::backend::crossterm::EventHandler;
use tui_input::{Input, InputRequest};

const REFRESH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone)]
enum Mode {
    Normal,
    ConfirmDelete,
    Rename(Input),
    Add(Input),
}

struct App {
    config: Config,
    selected: usize,
    scroll: usize,
    mode: Mode,
    message: Option<String>,
    path_completion: Option<PathCompletion>,
    clipboard: Option<arboard::Clipboard>,
}

struct TerminalSession;

#[derive(Clone)]
struct PathCompletion {
    candidates: Vec<CompletionCandidate>,
    index: usize,
}

#[derive(Clone)]
struct CompletionCandidate {
    value: String,
    cursor: usize,
}

impl App {
    fn new(config: Config) -> Self {
        Self {
            config,
            selected: 0,
            scroll: 0,
            mode: Mode::Normal,
            message: None,
            path_completion: None,
            clipboard: None,
        }
    }

    fn selected(&self) -> Option<&Credential> {
        self.config.credentials.get(self.selected)
    }

    fn keep_selection_valid(&mut self) {
        if self.config.credentials.is_empty() {
            self.selected = 0;
            self.scroll = 0;
        } else {
            self.selected = self.selected.min(self.config.credentials.len() - 1);
            self.scroll = self.scroll.min(self.selected);
        }
    }
}

impl TerminalSession {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode().context("Failed to enable terminal raw mode")?;
        if let Err(error) = execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableBracketedPaste,
            Hide
        ) {
            let _ = terminal::disable_raw_mode();
            return Err(error).context("Failed to initialize terminal display");
        }
        Ok(Self)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            SetAttribute(Attribute::Reset),
            DisableBracketedPaste,
            Show,
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

fn safe_text(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn fit_line(text: &str, width: u16) -> String {
    let width = width as usize;
    let mut line = safe_text(text).chars().take(width).collect::<String>();
    let length = line.chars().count();
    line.extend(std::iter::repeat_n(' ', width.saturating_sub(length)));
    line
}

fn draw_input(
    stdout: &mut Stdout,
    row: u16,
    width: u16,
    prefix: &str,
    input: &Input,
) -> Result<()> {
    let prefix = safe_text(prefix);
    let prefix_width = prefix.chars().count().min(width as usize) as u16;
    queue!(
        stdout,
        MoveTo(0, row),
        SetAttribute(Attribute::Bold),
        Print(
            prefix
                .chars()
                .take(prefix_width as usize)
                .collect::<String>()
        ),
        SetAttribute(Attribute::Reset)
    )?;

    let input_width = width.saturating_sub(prefix_width);
    if input_width > 0 {
        tui_input::backend::crossterm::write(
            stdout,
            input.value(),
            input.cursor(),
            (prefix_width, row),
            input_width,
        )?;
    }
    Ok(())
}

fn path_completion_candidates(input: &Input) -> Result<Vec<CompletionCandidate>> {
    let cursor_byte = input
        .value()
        .char_indices()
        .nth(input.cursor())
        .map_or(input.value().len(), |(index, _)| index);
    let (before_cursor, after_cursor) = input.value().split_at(cursor_byte);
    if before_cursor.starts_with("otpauth://") || before_cursor.starts_with("otpauth-migration://")
    {
        return Ok(Vec::new());
    }

    let separator = std::path::MAIN_SEPARATOR;
    let (directory, prefix, base) = if before_cursor.is_empty() {
        (Path::new("."), "", "")
    } else if before_cursor.ends_with(separator) {
        (Path::new(before_cursor), "", before_cursor)
    } else {
        let path = Path::new(before_cursor);
        let prefix = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let base = &before_cursor[..before_cursor.len().saturating_sub(prefix.len())];
        (directory, prefix, base)
    };

    let directory = expand_home(directory)?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to read directory {}", directory.display()));
        }
    };
    let include_hidden = prefix.starts_with('.');
    let mut candidates = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            if !name.starts_with(prefix) || (!include_hidden && name.starts_with('.')) {
                return None;
            }
            let directory_suffix = if entry.path().is_dir() {
                separator.to_string()
            } else {
                String::new()
            };
            let completed_prefix = format!("{base}{name}{directory_suffix}");
            Some(CompletionCandidate {
                cursor: completed_prefix.chars().count(),
                value: format!("{completed_prefix}{after_cursor}"),
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.value.cmp(&right.value));
    Ok(candidates)
}

fn cycle_path_completion(
    input: &mut Input,
    completion: &mut Option<PathCompletion>,
    backwards: bool,
) -> Result<Option<String>> {
    let descend_into_only_match = completion.as_ref().is_some_and(|state| {
        state.candidates.len() == 1
            && input.value() == state.candidates[0].value
            && input.cursor() == state.candidates[0].cursor
            && input.cursor() == input.value().chars().count()
            && input.value().ends_with(std::path::MAIN_SEPARATOR)
    });

    if completion.is_none() || descend_into_only_match {
        let candidates = path_completion_candidates(input)?;
        if candidates.is_empty() {
            *completion = None;
            return Ok(None);
        }
        let index = if backwards { candidates.len() - 1 } else { 0 };
        *input = Input::new(candidates[index].value.clone()).with_cursor(candidates[index].cursor);
        *completion = Some(PathCompletion { candidates, index });
    } else if let Some(state) = completion {
        state.index = if backwards {
            state
                .index
                .checked_sub(1)
                .unwrap_or(state.candidates.len() - 1)
        } else {
            (state.index + 1) % state.candidates.len()
        };
        let candidate = &state.candidates[state.index];
        *input = Input::new(candidate.value.clone()).with_cursor(candidate.cursor);
    }

    Ok(completion
        .as_ref()
        .map(|state| format!("Path match {}/{}", state.index + 1, state.candidates.len())))
}

fn current_code(credential: &Credential) -> Result<(String, u64)> {
    let totp = Totp::from_url_unchecked(&credential.url).context("Invalid credential URL")?;
    Ok((totp.generate_current().to_string(), totp.ttl()))
}

fn credential_code(credential: &Credential) -> String {
    match current_code(credential) {
        Ok((code, ttl)) => format!("{code} TTL: {ttl}s"),
        Err(_) => "Invalid credential URL".to_owned(),
    }
}

fn copy_selected_code(app: &mut App) -> Result<()> {
    let code = current_code(app.selected().context("No credential selected")?)?.0;
    if app.clipboard.is_none() {
        app.clipboard = Some(arboard::Clipboard::new().context("Failed to access clipboard")?);
    }
    app.clipboard
        .as_mut()
        .context("Failed to access clipboard")?
        .set_text(code)
        .context("Failed to copy code")
}

fn draw(app: &mut App, stdout: &mut Stdout) -> Result<()> {
    let (width, height) = terminal::size().context("Failed to read terminal size")?;
    queue!(stdout, Hide, Clear(ClearType::All))?;
    if width == 0 || height == 0 {
        stdout.flush()?;
        return Ok(());
    }

    let header = match (&app.mode, &app.message) {
        (Mode::Normal, _) | (_, None) => "OTPC | q quit | n add | s scan screen".to_owned(),
        (_, Some(message)) => format!("OTPC | q quit | n add | s scan screen | {message}"),
    };
    queue!(
        stdout,
        MoveTo(0, 0),
        SetAttribute(Attribute::Bold),
        Print(fit_line(&header, width)),
        SetAttribute(Attribute::Reset)
    )?;
    if height > 1 {
        queue!(
            stdout,
            MoveTo(0, 1),
            Print(std::iter::repeat_n('─', width as usize).collect::<String>())
        )?;
    }

    let body_height = height.saturating_sub(3) as usize;
    let visible_count = ((body_height + 1) / 3).max(1);
    if app.selected < app.scroll {
        app.scroll = app.selected;
    } else if app.selected >= app.scroll + visible_count {
        app.scroll = app.selected + 1 - visible_count;
    }

    if app.config.credentials.is_empty() && height > 3 {
        queue!(
            stdout,
            MoveTo(0, 2),
            Print(fit_line("No credentials. Press n to add one.", width))
        )?;
    } else {
        for (slot, (index, credential)) in app
            .config
            .credentials
            .iter()
            .enumerate()
            .skip(app.scroll)
            .take(visible_count)
            .enumerate()
        {
            let row = 2 + (slot * 3) as u16;
            if row >= height.saturating_sub(1) {
                break;
            }
            if index == app.selected {
                queue!(stdout, SetAttribute(Attribute::Reverse))?;
            }
            queue!(
                stdout,
                SetAttribute(Attribute::Bold),
                MoveTo(0, row),
                Print(fit_line(
                    &format!("{}: {}", credential.issuer, credential.name),
                    width
                )),
                SetAttribute(Attribute::NormalIntensity)
            )?;
            if row + 1 < height.saturating_sub(1) {
                queue!(
                    stdout,
                    MoveTo(0, row + 1),
                    Print(fit_line(&credential_code(credential), width))
                )?;
            }
            queue!(stdout, SetAttribute(Attribute::Reset))?;
        }
    }

    let footer_row = height - 1;
    let footer = match &app.mode {
        Mode::Normal => {
            let options = if app.selected().is_some() {
                "[enter] copy | d delete | r rename"
            } else {
                ""
            };
            let footer = match &app.message {
                Some(message) if !options.is_empty() => format!("{options} | {message}"),
                Some(message) => message.clone(),
                None => options.to_owned(),
            };
            Some(fit_line(&footer, width))
        }
        Mode::ConfirmDelete => {
            let target = app
                .selected()
                .map(|credential| format!("{}: {}", credential.issuer, credential.name))
                .unwrap_or_default();
            Some(fit_line(&format!("Delete {target}? (y/n)"), width))
        }
        Mode::Rename(input) => {
            draw_input(stdout, footer_row, width, "Rename: ", input)?;
            None
        }
        Mode::Add(input) => {
            draw_input(stdout, footer_row, width, "Add URL or image path: ", input)?;
            None
        }
    };
    if let Some(footer) = footer {
        queue!(
            stdout,
            MoveTo(0, footer_row),
            SetAttribute(Attribute::Bold),
            Print(footer),
            SetAttribute(Attribute::Reset)
        )?;
    }
    stdout.flush().context("Failed to draw terminal UI")
}

fn save_or_restore(app: &mut App, entry: &Entry, previous: Config, success: String) -> bool {
    match write_config(entry, &app.config) {
        Ok(()) => {
            app.message = Some(success);
            true
        }
        Err(error) => {
            app.config = previous;
            app.keep_selection_valid();
            app.message = Some(format!("Save failed: {error:#}"));
            false
        }
    }
}

fn add_credentials(app: &mut App, entry: &Entry, credentials: Vec<crate::NewCredential>) -> bool {
    let previous = app.config.clone();
    match app.config.add(credentials) {
        Ok(count) => {
            app.selected = app.config.credentials.len() - 1;
            save_or_restore(app, entry, previous, format!("Added {count} credential(s)"))
        }
        Err(error) => {
            app.message = Some(error.to_string());
            false
        }
    }
}

fn handle_key(app: &mut App, entry: &Entry, key: KeyEvent) -> bool {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return true;
    }
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }

    match app.mode.clone() {
        Mode::Normal => match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Char('n') => {
                app.mode = Mode::Add(Input::default());
                app.message = None;
                app.path_completion = None;
            }
            KeyCode::Char('s') => match credentials_from_screenshot() {
                Ok(credentials) => {
                    add_credentials(app, entry, credentials);
                }
                Err(error) => {
                    app.message = Some(format!("Screen scan failed: {error:#}"));
                }
            },
            KeyCode::Enter if app.selected().is_some() => match copy_selected_code(app) {
                Ok(()) => app.message = Some("Code copied".to_owned()),
                Err(error) => app.message = Some(format!("Copy failed: {error:#}")),
            },
            KeyCode::Down | KeyCode::Char('j')
                if app.selected + 1 < app.config.credentials.len() =>
            {
                app.selected += 1;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.selected = app.selected.saturating_sub(1);
            }
            KeyCode::Char('d') if app.selected().is_some() => {
                app.mode = Mode::ConfirmDelete;
                app.message = None;
            }
            KeyCode::Char('r') => {
                if let Some(credential) = app.selected() {
                    app.mode = Mode::Rename(Input::new(credential.name.clone()));
                    app.message = None;
                }
            }
            _ => {}
        },
        Mode::ConfirmDelete => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if app.selected().is_some() {
                    let previous = app.config.clone();
                    let removed = app.config.credentials.remove(app.selected);
                    app.keep_selection_valid();
                    save_or_restore(
                        app,
                        entry,
                        previous,
                        format!("Deleted {}: {}", removed.issuer, removed.name),
                    );
                }
                app.mode = Mode::Normal;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.mode = Mode::Normal;
            }
            _ => {}
        },
        Mode::Rename(mut input) => match key.code {
            KeyCode::Esc => {
                app.mode = Mode::Normal;
                app.message = None;
            }
            KeyCode::Enter => {
                let name = input.value().trim().to_owned();
                if name.is_empty() {
                    app.message = Some("Display name cannot be empty".to_owned());
                    app.mode = Mode::Rename(input);
                } else if app.selected().is_some() {
                    let previous = app.config.clone();
                    app.config.credentials[app.selected].name = name;
                    if save_or_restore(app, entry, previous, "Credential renamed".to_owned()) {
                        app.mode = Mode::Normal;
                    } else {
                        app.mode = Mode::Rename(input);
                    }
                }
            }
            _ => {
                input.handle_event(&Event::Key(key));
                app.mode = Mode::Rename(input);
            }
        },
        Mode::Add(mut input) => match key.code {
            KeyCode::Esc => {
                app.mode = Mode::Normal;
                app.message = None;
                app.path_completion = None;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let backwards = key.code == KeyCode::BackTab;
                match cycle_path_completion(&mut input, &mut app.path_completion, backwards) {
                    Ok(Some(message)) => app.message = Some(message),
                    Ok(None) => app.message = Some("No path matches".to_owned()),
                    Err(error) => {
                        app.message = Some(format!("Path completion failed: {error:#}"));
                    }
                }
                app.mode = Mode::Add(input);
            }
            KeyCode::Enter => {
                let source = input.value().trim().to_owned();
                if source.is_empty() {
                    app.message = Some("Enter a URL or image path".to_owned());
                    app.mode = Mode::Add(input);
                } else {
                    match credentials_from_source(&source) {
                        Ok(credentials) => {
                            if add_credentials(app, entry, credentials) {
                                app.mode = Mode::Normal;
                                app.path_completion = None;
                            } else {
                                app.mode = Mode::Add(input);
                            }
                        }
                        Err(error) => {
                            app.message = Some(format!("Add failed: {error:#}"));
                            app.mode = Mode::Add(input);
                        }
                    }
                }
            }
            _ => {
                input.handle_event(&Event::Key(key));
                app.mode = Mode::Add(input);
                app.message = None;
                app.path_completion = None;
            }
        },
    }

    true
}

fn handle_event(app: &mut App, entry: &Entry, event: Event) -> bool {
    match event {
        Event::Key(key) => handle_key(app, entry, key),
        Event::Paste(text) => {
            match &mut app.mode {
                Mode::Rename(input) | Mode::Add(input) => {
                    for character in text.trim().chars() {
                        input.handle(InputRequest::InsertChar(character));
                    }
                    app.path_completion = None;
                }
                _ => {}
            }
            true
        }
        _ => true,
    }
}

pub(crate) fn run(entry: &Entry, config: Config) -> Result<()> {
    let _terminal = TerminalSession::enter()?;
    let mut stdout = io::stdout();
    let mut app = App::new(config);

    loop {
        draw(&mut app, &mut stdout)?;
        if event::poll(REFRESH_INTERVAL).context("Failed to poll terminal events")? {
            let event = event::read().context("Failed to read terminal event")?;
            if !handle_event(&mut app, entry, event) {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_and_cycles_path_matches() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let mut input = Input::new(format!("{manifest_dir}/Cargo."));
        let mut completion = None;

        let message = cycle_path_completion(&mut input, &mut completion, false).unwrap();

        assert!(message.is_some());
        assert_eq!(input.value(), format!("{manifest_dir}/Cargo.lock"));

        cycle_path_completion(&mut input, &mut completion, false).unwrap();
        assert_eq!(input.value(), format!("{manifest_dir}/Cargo.toml"));

        cycle_path_completion(&mut input, &mut completion, false).unwrap();
        assert_eq!(input.value(), format!("{manifest_dir}/Cargo.lock"));
    }

    #[test]
    fn completes_at_the_cursor_without_discarding_the_suffix() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let prefix = format!("{manifest_dir}/Cargo.");
        let mut input = Input::new(format!("{prefix}suffix")).with_cursor(prefix.chars().count());
        let mut completion = None;

        cycle_path_completion(&mut input, &mut completion, false).unwrap();

        assert_eq!(input.value(), format!("{manifest_dir}/Cargo.locksuffix"));
        assert_eq!(
            input.cursor(),
            format!("{manifest_dir}/Cargo.lock").chars().count()
        );
    }
}
