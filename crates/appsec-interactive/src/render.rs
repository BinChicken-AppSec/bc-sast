use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub finding_index: i64,
    pub severity: String,
    pub title: String,
    pub file: String,
    pub done: bool,
}

const GREEN: &str = "\x1b[32m";
const DIM: &str = "\x1b[2m";
const INV: &str = "\x1b[7m";
const RST: &str = "\x1b[0m";

pub fn render_rows(rows: &[Row], cursor: Option<usize>) -> Vec<String> {
    rows.iter()
        .enumerate()
        .map(|(i, r)| {
            let mark = if r.done {
                format!("{GREEN}✅{RST}")
            } else {
                "  ".to_string()
            };
            let mut line = format!(
                "{:>3}  {mark}  [{:<8}] {}",
                r.finding_index, r.severity, r.title
            );
            if !r.file.is_empty() {
                line.push_str(&format!("  {DIM}({}){RST}", r.file));
            }
            if cursor == Some(i) {
                format!("{INV}\u{2771} {line}{RST}")
            } else {
                format!("  {line}")
            }
        })
        .collect()
}

pub fn render_frame(rows: &[Row], cursor: usize) -> String {
    let done = rows.iter().filter(|r| r.done).count();
    let mut out = format!(
        "  Remediation Agent remediation — {} issue(s), {done} done\n",
        rows.len()
    );
    out.push_str(&format!(
        "  {DIM}\u{2191}/\u{2193} move \u{b7} Enter remediate \u{b7} q quit{RST}\n\n"
    ));
    for row in render_rows(rows, Some(cursor)) {
        out.push_str(&row);
        out.push('\n');
    }
    out
}

pub fn parse_selection(text: &str, rows: &[Row]) -> Option<Vec<usize>> {
    let t = text.trim().to_lowercase();
    if matches!(t.as_str(), "q" | "quit" | "exit" | "") {
        return None;
    }
    if t == "all" {
        return Some((0..rows.len()).collect());
    }
    if t == "pending" {
        return Some(
            rows.iter()
                .enumerate()
                .filter(|(_, r)| !r.done)
                .map(|(i, _)| i)
                .collect(),
        );
    }

    let by_index: HashMap<i64, usize> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.finding_index, i))
        .collect();
    let mut chosen = Vec::new();
    for tok in t.split(|c: char| c == ',' || c.is_whitespace()) {
        if tok.is_empty() {
            continue;
        }
        if let Some((a, b)) = tok.split_once('-') {
            let (Ok(lo), Ok(hi)) = (a.parse::<i64>(), b.parse::<i64>()) else {
                continue;
            };
            for idx in lo..=hi {
                push_if_new(&by_index, idx, &mut chosen);
            }
        } else if let Ok(idx) = tok.parse::<i64>() {
            push_if_new(&by_index, idx, &mut chosen);
        }
    }
    Some(chosen)
}

fn push_if_new(by_index: &HashMap<i64, usize>, idx: i64, chosen: &mut Vec<usize>) {
    if let Some(&pos) = by_index.get(&idx) {
        if !chosen.contains(&pos) {
            chosen.push(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(finding_index: i64, done: bool) -> Row {
        Row {
            finding_index,
            severity: "HIGH".to_string(),
            title: format!("finding {finding_index}"),
            file: format!("f{finding_index}.py"),
            done,
        }
    }

    #[test]
    fn render_rows_of_an_empty_slice_is_empty() {
        assert!(render_rows(&[], None).is_empty());
    }

    #[test]
    fn render_rows_shows_a_checkmark_only_for_done_rows() {
        let rows = [row(1, false), row(2, true)];
        let rendered = render_rows(&rows, None);
        assert!(!rendered[0].contains('\u{2705}'));
        assert!(rendered[1].contains('\u{2705}'));
    }

    #[test]
    fn render_rows_includes_severity_title_and_file() {
        let rows = [row(1, false)];
        let rendered = render_rows(&rows, None);
        assert!(rendered[0].contains("HIGH"));
        assert!(rendered[0].contains("finding 1"));
        assert!(rendered[0].contains("f1.py"));
    }

    #[test]
    fn render_rows_omits_the_file_parens_when_file_is_empty() {
        let mut r = row(1, false);
        r.file = String::new();
        let rendered = render_rows(std::slice::from_ref(&r), None);
        assert!(!rendered[0].contains('('));
    }

    #[test]
    fn render_rows_highlights_only_the_cursor_row() {
        let rows = [row(1, false), row(2, false)];
        let rendered = render_rows(&rows, Some(1));
        assert!(!rendered[0].contains('\u{2771}'));
        assert!(rendered[1].contains('\u{2771}'));
    }

    #[test]
    fn render_frame_reports_the_total_and_done_counts() {
        let rows = [row(1, true), row(2, false), row(3, true)];
        let frame = render_frame(&rows, 0);
        assert!(frame.contains("3 issue(s)"));
        assert!(frame.contains("2 done"));
    }

    #[test]
    fn render_frame_includes_every_row() {
        let rows = [row(1, false), row(2, false)];
        let frame = render_frame(&rows, 0);
        assert!(frame.contains("finding 1"));
        assert!(frame.contains("finding 2"));
    }

    #[test]
    fn parse_selection_of_q_variants_and_blank_signals_quit() {
        let rows = [row(1, false)];
        for text in ["q", "Q", "quit", "EXIT", "", "   "] {
            assert_eq!(parse_selection(text, &rows), None, "text={text:?}");
        }
    }

    #[test]
    fn parse_selection_all_selects_every_row_in_order() {
        let rows = [row(1, false), row(2, false), row(3, false)];
        assert_eq!(parse_selection("all", &rows), Some(vec![0, 1, 2]));
    }

    #[test]
    fn parse_selection_pending_selects_only_not_done_rows() {
        let rows = [row(1, true), row(2, false), row(3, false)];
        assert_eq!(parse_selection("pending", &rows), Some(vec![1, 2]));
    }

    #[test]
    fn parse_selection_a_comma_list_resolves_by_finding_index() {
        let rows = [row(10, false), row(20, false), row(30, false)];
        assert_eq!(parse_selection("10,30", &rows), Some(vec![0, 2]));
    }

    #[test]
    fn parse_selection_accepts_whitespace_as_a_separator_too() {
        let rows = [row(1, false), row(2, false)];
        assert_eq!(parse_selection("1 2", &rows), Some(vec![0, 1]));
    }

    #[test]
    fn parse_selection_a_range_expands_inclusive() {
        let rows = [row(1, false), row(2, false), row(3, false), row(4, false)];
        assert_eq!(parse_selection("2-3", &rows), Some(vec![1, 2]));
    }

    #[test]
    fn parse_selection_a_reversed_range_selects_nothing() {
        let rows = [row(1, false), row(2, false)];
        assert_eq!(parse_selection("2-1", &rows), Some(vec![]));
    }

    #[test]
    fn parse_selection_dedupes_repeated_and_overlapping_picks() {
        let rows = [row(1, false), row(2, false), row(3, false)];
        assert_eq!(parse_selection("1,1-2,2", &rows), Some(vec![0, 1]));
    }

    #[test]
    fn parse_selection_skips_out_of_range_and_garbage_tokens() {
        let rows = [row(1, false)];
        assert_eq!(parse_selection("1,99,abc,5-", &rows), Some(vec![0]));
    }

    #[test]
    fn parse_selection_of_only_separators_selects_nothing() {
        let rows = [row(1, false)];
        assert_eq!(parse_selection(",  ,", &rows), Some(vec![]));
    }
}
