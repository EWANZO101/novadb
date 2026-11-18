//! Server-rendered HTML. No JavaScript at all; every dynamic value goes through [`esc`].

use crate::store::Role;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Short content hash of the stylesheet, used as a cache-buster in the `<link>` URL.
fn css_tag() -> &'static str {
    static TAG: OnceLock<String> = OnceLock::new();
    TAG.get_or_init(|| {
        Sha256::digest(crate::web::CSS.as_bytes())
            .iter()
            .take(5)
            .map(|b| format!("{b:02x}"))
            .collect()
    })
}

/// HTML-escape text and attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

pub struct Nav<'a> {
    pub user: &'a str,
    pub role: Role,
    pub csrf: &'a str,
    pub active: &'a str,
}

/// Hidden CSRF field.
pub fn csrf(token: &str) -> String {
    format!(
        r#"<input type="hidden" name="csrf" value="{}">"#,
        esc(token)
    )
}

pub enum Flash<'a> {
    None,
    Ok(&'a str),
    Err(&'a str),
}

/// Inline SVG icon (Lucide-style strokes). Unknown names render nothing.
pub fn icon(name: &str) -> String {
    let body = match name {
        "overview" => {
            r#"<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>"#
        }
        "audit" => {
            r#"<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>"#
        }
        "users" => {
            r#"<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>"#
        }
        "user" => {
            r#"<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>"#
        }
        "user-plus" => {
            r#"<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6"/><path d="M22 11h-6"/>"#
        }
        "logout" => {
            r#"<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>"#
        }
        "database" => {
            r#"<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>"#
        }
        "clock" => r#"<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>"#,
        "activity" => r#"<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>"#,
        "monitor" => {
            r#"<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>"#
        }
        "drive" => {
            r#"<path d="M22 12H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><path d="M6 16h.01"/><path d="M10 16h.01"/>"#
        }
        "file" => {
            r#"<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/>"#
        }
        "check" => r#"<path d="M20 6 9 17l-5-5"/>"#,
        "alert" => {
            r#"<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>"#
        }
        "x" => r#"<path d="M18 6 6 18"/><path d="m6 6 12 12"/>"#,
        "check-circle" => r#"<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>"#,
        "lock" => {
            r#"<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#
        }
        "key" => {
            r#"<path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"/><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/>"#
        }
        "phone" => r#"<rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/>"#,
        "link" => {
            r#"<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>"#
        }
        "more" => {
            r#"<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>"#
        }
        "flag" => {
            r#"<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>"#
        }
        "archive" => {
            r#"<rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/>"#
        }
        "network" => {
            r#"<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>"#
        }
        "terminal" => r#"<path d="m4 17 6-6-6-6"/><path d="M12 19h8"/>"#,
        "cpu" => {
            r#"<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/>"#
        }
        "download" => {
            r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>"#
        }
        "search" => r#"<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>"#,
        "life-buoy" => {
            r#"<circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><path d="m14.83 9.17 4.24-4.24"/><path d="m14.83 14.83 4.24 4.24"/><path d="m9.17 14.83-4.24 4.24"/><circle cx="12" cy="12" r="4"/>"#
        }
        "settings" => {
            r#"<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>"#
        }
        "zap" => {
            r#"<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>"#
        }
        _ => "",
    };
    format!(r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true">{body}</svg>"#)
}

/// Brand mark (gradient star over a stacked-disk silhouette). Presentation attributes only (CSP-safe).
pub fn logo() -> &'static str {
    r##"<svg class="logo" viewBox="0 0 32 32" aria-hidden="true"><defs><linearGradient id="ng" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8b7cff"/><stop offset="1" stop-color="#d06cff"/></linearGradient></defs><rect width="32" height="32" rx="9" fill="url(#ng)"/><path d="M16 6.5c.6 4.6 2.9 6.9 7.5 7.5-4.6.6-6.9 2.9-7.5 7.5-.6-4.6-2.9-6.9-7.5-7.5 4.6-.6 6.9-2.9 7.5-7.5z" fill="#fff"/><path d="M9 23.5c2 1.3 4.4 2 7 2s5-.7 7-2" stroke="#fff" stroke-opacity=".7" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>"##
}

fn brand() -> String {
    format!(
        r#"<a class="brand" href="/">{}<span class="brand-t"><b>NovaDB</b><small>Control plane</small></span></a>"#,
        logo()
    )
}

/// Up to two initials for an avatar bubble.
pub fn initials(name: &str) -> String {
    let parts: Vec<&str> = name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|p| !p.is_empty())
        .collect();
    let s: String = match parts.as_slice() {
        [] => "?".into(),
        [one] => one.chars().take(2).collect(),
        [a, b, ..] => a.chars().take(1).chain(b.chars().take(1)).collect(),
    };
    esc(&s.to_uppercase())
}

/// Avatar bubble for a user name.
pub fn avatar(name: &str) -> String {
    format!(
        r#"<span class="avatar" aria-hidden="true">{}</span>"#,
        initials(name)
    )
}

/// Page header: title, subtitle, optional right-hand slot.
pub fn header(title: &str, sub: &str, right: &str) -> String {
    format!(
        r#"<div class="ph"><div><h1>{}</h1><p class="sub">{sub}</p></div>{right}</div>"#,
        esc(title)
    )
}

pub fn page(title: &str, nav: Option<&Nav<'_>>, flash: Flash<'_>, body: &str) -> String {
    let flash_html = match flash {
        Flash::None => String::new(),
        Flash::Ok(m) => format!(
            r#"<div class="flash ok" role="status">{}<span>{}</span></div>"#,
            icon("check-circle"),
            esc(m)
        ),
        Flash::Err(m) => format!(
            r#"<div class="flash err" role="alert">{}<span>{}</span></div>"#,
            icon("alert"),
            esc(m)
        ),
    };
    let ver = env!("CARGO_PKG_VERSION");
    let inner = match nav {
        None => format!(
            r#"<div class="auth"><aside class="auth-art">{brand}
<div><h2>The database you can see all the way through.</h2>
<p>Self-hosted control plane for NovaDB: identity, sessions and a tamper-evident audit trail stored in NovaDB's own storage engine.</p>
<ul class="feats"><li>{i1}Mandatory two-factor on every account</li><li>{i2}Hash-chained, append-only audit log</li><li>{i3}Crash-safe WAL storage with full verify</li></ul></div>
<small class="legal">NovaDB v{ver} · restricted system · all access is logged</small></aside>
<div class="auth-main"><div class="auth-box">{brand}{flash_html}{body}<p class="authfoot">Protected by Argon2id + TOTP · all sign-ins are audited</p></div></div></div>"#,
            brand = brand(),
            i1 = icon("lock"),
            i2 = icon("audit"),
            i3 = icon("database"),
        ),
        Some(n) => {
            let mut links = vec![("/", "Overview", "overview")];
            if n.role >= Role::Operator {
                links.push(("/audit", "Audit log", "audit"));
            }
            if n.role >= Role::Admin {
                links.push(("/users", "Users", "users"));
                links.push(("/sessions", "Sessions", "monitor"));
            }
            if n.role >= Role::Operator {
                links.push(("/system", "System", "cpu"));
            }
            let items: String = links
                .iter()
                .map(|(href, label, ic)| {
                    let cls = if *href == n.active {
                        r#" class="on" aria-current="page""#
                    } else {
                        ""
                    };
                    format!(r#"<a href="{href}"{cls}>{}{label}</a>"#, icon(ic))
                })
                .collect();
            let acc_cls = if n.active == "/account" {
                r#" class="on" aria-current="page""#
            } else {
                ""
            };
            let current = match n.active {
                "/audit" => "Audit log",
                "/users" => "Users",
                "/account" => "Account",
                "/sessions" => "Sessions",
                "/system" => "System",
                _ => "Overview",
            };
            format!(
                r#"<div class="shell"><aside class="side">{brand}
<nav class="nav" aria-label="Main"><div class="nav-label">Control</div>{items}
<div class="nav-label">Engine</div><span class="dis">{idb}Databases<span class="soon">Soon</span></span><span class="dis">{ibk}Backups<span class="soon">Stage 7</span></span><span class="dis">{icl}Cluster<span class="soon">Stage 8</span></span>
<div class="nav-label">You</div><a href="/account"{acc_cls}>{iac}Account</a></nav>
<div class="side-foot"><div class="me">{av}<span class="me-t"><b>{user}</b><small>{role}</small></span>
<form method="post" action="/logout">{csrf}<button class="iconbtn" title="Sign out" aria-label="Sign out">{ilo}</button></form></div>
<div class="ver">{izp}NovaDB v{ver}</div></div></aside>
<div class="content"><header class="top"><div class="crumb">NovaDB<span class="sep">/</span><b>{current}</b></div>
<div class="top-r"><span class="badge ok"><span class="pulse"></span>Online</span></div></header>
<main>{flash_html}{body}</main>
<footer class="foot"><span>NovaDB control dashboard v{ver}</span><span>Times shown in UTC</span></footer></div></div>"#,
                brand = brand(),
                idb = icon("database"),
                ibk = icon("archive"),
                icl = icon("network"),
                iac = icon("user"),
                ilo = icon("logout"),
                izp = icon("zap"),
                av = avatar(n.user),
                user = esc(n.user),
                role = n.role.name(),
                csrf = csrf(n.csrf),
            )
        }
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="dark light"><title>{} · NovaDB</title><link rel="stylesheet" href="/static/app.css?v={}"></head>
<body>{inner}</body></html>"#,
        esc(title),
        css_tag()
    )
}

/// Badge class for an audit action (failures and blocks stand out).
pub fn event_class(action: &str) -> &'static str {
    if action.contains("fail") || action.contains("locked") || action.contains("rate") {
        "bad"
    } else if action.starts_with("login.ok")
        || action.ends_with("enrolled")
        || action.ends_with("created")
    {
        "ok"
    } else if action.contains("reset")
        || action.contains("revoked")
        || action.contains("disable")
        || action.contains("delete")
        || action.contains("recovery")
    {
        "warn"
    } else {
        ""
    }
}

/// Human-readable byte count.
pub fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// UTC timestamp `YYYY-MM-DD HH:MM:SS`.
pub fn ts(secs: u64) -> String {
    if secs == 0 {
        return "never".into();
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// "3m ago" style.
pub fn ago(now: u64, then: u64) -> String {
    if then == 0 {
        return "never".into();
    }
    let d = now.saturating_sub(then);
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86_399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(
            esc(r#"<script>"x"&'y'</script>"#),
            "&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;&lt;/script&gt;"
        );
    }

    #[test]
    fn times() {
        assert_eq!(ts(0), "never");
        assert_eq!(ts(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(ts(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(ago(100, 40), "1m ago");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(initials("jack.silver"), "JS");
        assert_eq!(initials("admin"), "AD");
        assert_eq!(initials("<x>"), "X");
    }
}
