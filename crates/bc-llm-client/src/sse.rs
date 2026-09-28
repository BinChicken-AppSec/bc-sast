//! A minimal, incremental `text/event-stream` (SSE) framer — the one
//! piece both streaming dialects need and neither should own.
//!
//! Hand-rolled rather than pulled from a crate, for the same reason
//! `bc-cli`'s own `csv_parse` is: this is a small, fully-specified,
//! fully-testable parsing task on a wire format that has not changed
//! since 2015, and the project's supply-chain policy prefers a narrow
//! primitive over a fresh dependency for exactly that shape of problem.
//!
//! Deliberately scoped to what the two Messages/chat-completions
//! dialects actually send: `data:` payloads. The `event:` line is
//! ignored because both providers repeat the event type inside the JSON
//! payload itself (`{"type":"content_block_delta",...}`), so parsing
//! from the payload keeps one source of truth instead of two that can
//! disagree. `id:` and `retry:` are ignored because neither dialect
//! supports resuming a dropped completion stream — a broken stream is
//! retried as a whole request by `bc-llm-agentic`, not resumed mid-way.
//!
//! Bytes in, not `&str`: a chunk boundary can fall in the middle of a
//! multi-byte UTF-8 character, so only COMPLETE lines are decoded (and
//! then lossily — a provider emitting invalid UTF-8 mid-token should
//! cost a replacement character, not the whole response).

/// Feeds response-body chunks in, yields complete SSE event payloads out.
#[derive(Debug, Default)]
pub struct SseDecoder {
    /// Bytes received but not yet terminated by a newline.
    partial: Vec<u8>,
    /// `data:` lines of the event currently being accumulated. The SSE
    /// spec allows several per event, joined by newlines — neither
    /// dialect sends more than one, but honoring it costs nothing and
    /// silently dropping the tail would be a corrupt payload.
    data: Vec<String>,
}

impl SseDecoder {
    pub fn new() -> Self {
        SseDecoder::default()
    }

    /// Consume one chunk of the response body, returning every event
    /// payload it completed, in order. An empty return is normal and
    /// common — an event's bytes routinely span several chunks.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.partial.extend_from_slice(chunk);
        let mut events = Vec::new();
        // `split` on the newline, keeping the last (unterminated) piece
        // as the new `partial`.
        while let Some(pos) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line);
            if let Some(event) = self.push_line(line.trim_end_matches(['\n', '\r'])) {
                events.push(event);
            }
        }
        events
    }

    /// Finish a stream whose last event arrived without its terminating
    /// blank line. Providers do send the blank line, but a connection
    /// closed the instant after the final `data:` line would otherwise
    /// lose that event — and for these dialects the final event is the
    /// one carrying the stop reason and the usage totals.
    pub fn finish(&mut self) -> Option<String> {
        let trailing = std::mem::take(&mut self.partial);
        if !trailing.is_empty() {
            let line = String::from_utf8_lossy(&trailing);
            let line = line.trim_end_matches(['\n', '\r']).to_string();
            // A trailing line can only ever complete the current event's
            // data, never terminate it (that needs a blank line), so any
            // event it yields is returned by the flush below instead.
            let _ = self.push_line(&line);
        }
        (!self.data.is_empty()).then(|| std::mem::take(&mut self.data).join("\n"))
    }

    /// One complete line, newline already stripped. Returns the finished
    /// event payload when this line was the blank line that ends one.
    fn push_line(&mut self, line: &str) -> Option<String> {
        if line.is_empty() {
            return (!self.data.is_empty()).then(|| std::mem::take(&mut self.data).join("\n"));
        }
        // A `:`-prefixed line is an SSE comment — providers use it as a
        // keep-alive heartbeat, which is precisely the traffic streaming
        // exists to keep flowing, so it is skipped without ending the
        // event in progress.
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            // A field with no colon is a field with an empty value.
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
        // `data` alone is a data line with an empty value, per the spec.
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
        let (head, tail) = payload.split_at(8); // mid-emoji
        assert!(d.push(head).is_empty());
        assert_eq!(d.push(tail), vec!["\u{1F600}"]);
    }
}
