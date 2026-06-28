use ratatui::style::{Color, Modifier, Style};

/// TUI color theme for the interactive mode.
///
/// Inspired by Dracula palette; used by all rendering widgets.
#[derive(Clone, Copy)]
pub struct Theme {
    /// Primary highlight (cyan)
    pub primary: Color,
    /// Secondary highlight (green)
    pub secondary: Color,
    /// Accent / warning (orange)
    pub accent: Color,
    /// Error / rejected (red)
    pub error: Color,
    /// Default foreground text
    pub text: Color,
    /// Muted / status text
    pub muted: Color,
    /// Border color for panels
    pub border: Color,
    /// Background color
    pub bg: Color,
}

#[allow(dead_code)]
impl Theme {
    pub fn dark() -> Self {
        Self {
            primary: Color::Rgb(0x8b, 0xe9, 0xfd),
            secondary: Color::Rgb(0x50, 0xfa, 0x7b),
            accent: Color::Rgb(0xff, 0xb8, 0x6c),
            error: Color::Rgb(0xff, 0x55, 0x55),
            text: Color::Rgb(0xf8, 0xf8, 0xf2),
            muted: Color::Rgb(0x62, 0x72, 0xa4),
            border: Color::Rgb(0x44, 0x47, 0x5a),
            bg: Color::Rgb(0x28, 0x2a, 0x36),
        }
    }

    pub fn bg_style(&self) -> Style {
        Style::default().bg(self.bg)
    }

    pub fn style_primary(&self) -> Style {
        Style::default().fg(self.primary)
    }

    pub fn style_secondary(&self) -> Style {
        Style::default().fg(self.secondary)
    }

    pub fn style_accent(&self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn style_error(&self) -> Style {
        Style::default().fg(self.error)
    }

    pub fn style_text(&self) -> Style {
        Style::default().fg(self.text)
    }

    pub fn style_muted(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn style_border(&self) -> Style {
        Style::default().fg(self.border)
    }

    pub fn style_bold_primary(&self) -> Style {
        Style::default().fg(self.primary).add_modifier(Modifier::BOLD)
    }

    pub fn style_bold_secondary(&self) -> Style {
        Style::default().fg(self.secondary).add_modifier(Modifier::BOLD)
    }

    pub fn style_bold_accent(&self) -> Style {
        Style::default().fg(self.accent).add_modifier(Modifier::BOLD)
    }

    pub fn style_bold_error(&self) -> Style {
        Style::default().fg(self.error).add_modifier(Modifier::BOLD)
    }
}
