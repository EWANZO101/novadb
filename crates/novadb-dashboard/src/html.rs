//! Server-rendered HTML. No JavaScript at all; every dynamic value goes through [`esc`].

use crate::store::Role;

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

pub fn page(title: &str, nav: Option<&Nav<'_>>, flash: Flash<'_>, body: &str) -> String {
    let nav_html = match nav {
        None => String::new(),
        Some(n) => {
            let mut links = vec![("/", "Overview")];
            if n.role >= Role::Operator {
                links.push(("/audit", "Audit log"));
            }
            if n.role >= Role::Admin {
                links.push(("/users", "Users"));
            }
            links.push(("/account", "Account"));
            let items: String = links
                .iter()
                .map(|(href, label)| {
                    let cls = if *href == n.active {
                        " class=\"on\""
                    } else {
                        ""
                    };
                    format!(r#"<a href="{href}"{cls}>{label}</a>"#)
                })
                .collect();
            format!(
                r#"<nav><div class="brand"><span class="dot"></span>NovaDB</div><div class="links">{items}</div>
<form method="post" action="/logout" class="who">{}<span>{} <em>{}</em></span><button class="ghost">Sign out</button></form></nav>"#,
                csrf(n.csrf),
                esc(n.user),
                n.role.name()
            )
        }
    };
    let flash_html = match flash {
        Flash::None => String::new(),
        Flash::Ok(m) => format!(r#"<div class="flash ok">{}</div>"#, esc(m)),
        Flash::Err(m) => format!(r#"<div class="flash err">{}</div>"#, esc(m)),
    };
    let main_cls = if nav.is_some() { "app" } else { "narrow" };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>{} · NovaDB</title><link rel="stylesheet" href="/static/app.css"></head>
<body>{nav_html}<main class="{main_cls}">{flash_html}{body}</main>
<footer>NovaDB control dashboard · v{}</footer></body></html>"#,
        esc(title),
        env!("CARGO_PKG_VERSION")
    )
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
    }
}
