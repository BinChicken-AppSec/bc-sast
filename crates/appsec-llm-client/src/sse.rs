#[derive(Debug, Default)]
pub struct SseDecoder {
    partial: Vec<u8>,
    data: Vec<String>,
}

impl SseDecoder {
    pub fn new() -> Self {
        SseDecoder::default()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.partial.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(pos) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line);
            if let Some(event) = self.push_line(line.trim_end_matches(['\n', '\r'])) {
                events.push(event);
            }
        }
        events
    }

    pub fn finish(&mut self) -> Option<String> {
        let trailing = std::mem::take(&mut self.partial);
        if !trailing.is_empty() {
            let line = String::from_utf8_lossy(&trailing);
            let line = line.trim_end_matches(['\n', '\r']).to_string();
            let _ = self.push_line(&line);
        }
        (!self.data.is_empty()).then(|| std::mem::take(&mut self.data).join("\n"))
    }

    fn push_line(&mut self, line: &str) -> Option<String> {
        if line.is_empty() {
            return (!self.data.is_empty()).then(|| std::mem::take(&mut self.data).join("\n"));
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        if field == "data" {
            self.data.push(value.to_string());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_event_in_one_chunk() {
        let mut d = SseDecoder::new();
        assert_eq!(d.push(b"data: {\"a\":1}\n\n"), vec!["{\"a\":1}"]);
    }

    #[test]
    fn an_event_split_across_chunk_boundaries() {
        let mut d = SseDecoder::new();
        assert!(d.push(b"data: {\"a\"").is_empty());
        assert!(d.push(b":1}").is_empty());
        assert_eq!(d.push(b"\n\n"), vec!["{\"a\":1}"]);
    }

    #[test]
    fn several_events_in_one_chunk_come_back_in_order() {
        let mut d = SseDecoder::new();
        assert_eq!(d.push(b"data: one\n\ndata: two\n\n"), vec!["one", "two"]);
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let mut d = SseDecoder::new();
        assert_eq!(d.push(b"data: one\r\n\r\n"), vec!["one"]);
    }

    #[test]
    fn the_event_field_and_other_fields_are_ignored() {
        let mut d = SseDecoder::new();
        assert_eq!(
            d.push(b"event: message_start\nid: 7\nretry: 100\ndata: payload\n\n"),
            vec!["payload"]
        );
    }

    #[test]
    fn a_comment_heartbeat_does_not_end_the_event_in_progress() {
        let mut d = SseDecoder::new();
        assert!(d.push(b"data: one\n").is_empty());
        assert!(d.push(b": ping\n").is_empty());
        assert_eq!(d.push(b"\n"), vec!["one"]);
    }

    #[test]
    fn several_data_lines_join_with_newlines() {
        let mut d = SseDecoder::new();
        assert_eq!(d.push(b"data: one\ndata: two\n\n"), vec!["one\ntwo"]);
    }

    #[test]
    fn a_field_with_no_colon_is_an_empty_value() {
        let mut d = SseDecoder::new();
        assert_eq!(d.push(b"data\n\n"), vec![""]);
    }

    #[test]
    fn a_blank_line_with_no_pending_data_yields_nothing() {
        let mut d = SseDecoder::new();
        assert!(d.push(b"\n\n\n").is_empty());
    }

    #[test]
    fn finish_flushes_an_event_that_never_got_its_blank_line() {
        let mut d = SseDecoder::new();
        assert!(d.push(b"data: last\n").is_empty());
        assert_eq!(d.finish().as_deref(), Some("last"));
        assert_eq!(d.finish(), None, "and only once");
    }

    #[test]
    fn finish_flushes_a_final_line_with_no_newline_at_all() {
        let mut d = SseDecoder::new();
        assert!(d.push(b"data: last").is_empty());
        assert_eq!(d.finish().as_deref(), Some("last"));
    }

    #[test]
    fn finish_on_a_cleanly_terminated_stream_yields_nothing() {
        let mut d = SseDecoder::new();
        assert_eq!(d.push(b"data: one\n\n"), vec!["one"]);
        assert_eq!(d.finish(), None);
    }

    #[test]
    fn finish_ignores_a_trailing_non_data_line() {
        let mut d = SseDecoder::new();
        assert!(d.push(b"event: done").is_empty());
        assert_eq!(d.finish(), None);
    }

    #[test]
    fn a_multibyte_character_split_across_chunks_survives() {
        let mut d = SseDecoder::new();
        let payload = "data: \u{1F600}\n\n".as_bytes();
        let (head, tail) = payload.split_at(8);
        assert!(d.push(head).is_empty());
        assert_eq!(d.push(tail), vec!["\u{1F600}"]);
    }
}
