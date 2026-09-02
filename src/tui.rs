use crate::{credentials_from_source, write_config, Config, Credential};
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
use std::io::{self, Stdout, Write};
use std::time::Duration;
use totp_rs::TOTP;

const REFRESH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone)]
enum Mode {
    Normal,
    ConfirmDelete,
    Rename(String),
    Add(String),
}

struct App {
    config: Config,
    selected: usize,
    scroll: usize,
    mode: Mode,
    message: Option<String>,
}

struct TerminalSession;

impl App {
    fn new(config: Config) -> Self {
        Self {
            config,
            selected: 0,
            scroll: 0,
            mode: Mode::Normal,
            message: None,
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

fn input_line(prefix: &str, input: &str, width: u16) -> (String, u16) {
    let available = (width as usize).saturating_sub(prefix.chars().count() + 1);
    let safe_input = safe_text(input);
    let input_length = safe_input.chars().count();
    let visible_input = safe_input
        .chars()
        .skip(input_length.saturating_sub(available))
        .collect::<String>();
    let line = fit_line(&format!("{prefix}{visible_input}"), width);
    let cursor = (prefix.chars().count() + visible_input.chars().count())
        .min(width.saturating_sub(1) as usize) as u16;
    (line, cursor)
}

fn credential_code(credential: &Credential) -> String {
    match TOTP::from_url_unchecked(&credential.url) {
        Ok(totp) => match (totp.generate_current(), totp.ttl()) {
            (Ok(code), Ok(ttl)) => format!("{code} TTL: {ttl}s"),
            _ => "Unable to generate code".to_owned(),
        },
        Err(_) => "Invalid credential URL".to_owned(),
    }
}

fn draw(app: &mut App, stdout: &mut Stdout) -> Result<()> {
    let (width, height) = terminal::size().context("Failed to read terminal size")?;
    queue!(stdout, Hide, Clear(ClearType::All))?;
    if width == 0 || height == 0 {
        stdout.flush()?;
        return Ok(());
    }

    let header = match (&app.mode, &app.message) {
        (Mode::Normal, _) | (_, None) => "q quit | n add".to_owned(),
        (_, Some(message)) => format!("q quit | n add | {message}"),
    };
    queue!(
        stdout,
        MoveTo(0, 0),
        SetAttribute(Attribute::Bold),
        Print(fit_line(&header, width)),
        SetAttribute(Attribute::Reset)
    )?;

    let body_height = height.saturating_sub(2) as usize;
    let visible_count = (body_height / 2).max(1);
    if app.selected < app.scroll {
        app.scroll = app.selected;
    } else if app.selected >= app.scroll + visible_count {
        app.scroll = app.selected + 1 - visible_count;
    }

    if app.config.credentials.is_empty() && height > 2 {
        queue!(
            stdout,
            MoveTo(0, 1),
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
            let row = 1 + (slot * 2) as u16;
            if row >= height.saturating_sub(1) {
                break;
            }
            if index == app.selected {
                queue!(stdout, SetAttribute(Attribute::Reverse))?;
            }
            queue!(
                stdout,
                MoveTo(0, row),
                Print(fit_line(
                    &format!("{}: {}", credential.issuer, credential.name),
                    width
                ))
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
    let (footer, cursor) = match &app.mode {
        Mode::Normal => {
            let options = if app.selected().is_some() {
                "d delete | r rename"
            } else {
                ""
            };
            let footer = match &app.message {
                Some(message) if !options.is_empty() => format!("{options} | {message}"),
                Some(message) => message.clone(),
                None => options.to_owned(),
            };
            (fit_line(&footer, width), None)
        }
        Mode::ConfirmDelete => {
            let target = app
                .selected()
                .map(|credential| format!("{}: {}", credential.issuer, credential.name))
                .unwrap_or_default();
            (fit_line(&format!("Delete {target}? (y/n)"), width), None)
        }
        Mode::Rename(input) => {
            let (line, column) = input_line("Rename: ", input, width);
            (line, Some(column))
        }
        Mode::Add(input) => {
            let (line, column) = input_line("Add URL or image path: ", input, width);
            (line, Some(column))
        }
    };
    queue!(
        stdout,
        MoveTo(0, footer_row),
        SetAttribute(Attribute::Bold),
        Print(footer),
        SetAttribute(Attribute::Reset)
    )?;
    if let Some(column) = cursor {
        queue!(stdout, MoveTo(column, footer_row), Show)?;
    }
    stdout.flush().context("Failed to draw terminal UI")
}

fn is_text_key(key: &KeyEvent) -> bool {
    !key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
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

fn handle_key(app: &mut App, entry: &Entry, key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press {
        return true;
    }
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }

    match app.mode.clone() {
        Mode::Normal => match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Char('n') => {
                app.mode = Mode::Add(String::new());
                app.message = None;
            }
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
                    app.mode = Mode::Rename(credential.name.clone());
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
            KeyCode::Backspace => {
                input.pop();
                app.mode = Mode::Rename(input);
            }
            KeyCode::Enter => {
                let name = input.trim();
                if name.is_empty() {
                    app.message = Some("Display name cannot be empty".to_owned());
                    app.mode = Mode::Rename(input);
                } else if app.selected().is_some() {
                    let previous = app.config.clone();
                    app.config.credentials[app.selected].name = name.to_owned();
                    if save_or_restore(app, entry, previous, "Credential renamed".to_owned()) {
                        app.mode = Mode::Normal;
                    } else {
                        app.mode = Mode::Rename(input);
                    }
                }
            }
            KeyCode::Char(character) if is_text_key(&key) => {
                input.push(character);
                app.mode = Mode::Rename(input);
            }
            _ => {}
        },
        Mode::Add(mut input) => match key.code {
            KeyCode::Esc => {
                app.mode = Mode::Normal;
                app.message = None;
            }
            KeyCode::Backspace => {
                input.pop();
                app.mode = Mode::Add(input);
            }
            KeyCode::Enter => {
                let source = input.trim();
                if source.is_empty() {
                    app.message = Some("Enter a URL or image path".to_owned());
                    app.mode = Mode::Add(input);
                } else {
                    match credentials_from_source(source) {
                        Ok(credentials) => {
                            let previous = app.config.clone();
                            match app.config.add(credentials) {
                                Ok(count) => {
                                    app.selected = app.config.credentials.len() - 1;
                                    if save_or_restore(
                                        app,
                                        entry,
                                        previous,
                                        format!("Added {count} credential(s)"),
                                    ) {
                                        app.mode = Mode::Normal;
                                    } else {
                                        app.mode = Mode::Add(input);
                                    }
                                }
                                Err(error) => {
                                    app.message = Some(error.to_string());
                                    app.mode = Mode::Add(input);
                                }
                            }
                        }
                        Err(error) => {
                            app.message = Some(format!("Add failed: {error:#}"));
                            app.mode = Mode::Add(input);
                        }
                    }
                }
            }
            KeyCode::Char(character) if is_text_key(&key) => {
                input.push(character);
                app.mode = Mode::Add(input);
            }
            _ => {}
        },
    }

    true
}

fn handle_event(app: &mut App, entry: &Entry, event: Event) -> bool {
    match event {
        Event::Key(key) => handle_key(app, entry, key),
        Event::Paste(text) => {
            match &mut app.mode {
                Mode::Rename(input) | Mode::Add(input) => input.push_str(text.trim()),
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
