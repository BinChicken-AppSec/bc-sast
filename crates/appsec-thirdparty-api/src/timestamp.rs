use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub(crate) fn chronological_key(raw: &str) -> (bool, i128) {
    match OffsetDateTime::parse(raw, &Rfc3339) {
        Ok(parsed) => (true, parsed.unix_timestamp_nanos()),
        Err(_) => (false, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_later_utc_timestamp_sorts_above_an_earlier_one() {
        assert!(
            chronological_key("2026-06-01T00:00:00Z") > chronological_key("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn offsets_are_normalized_rather_than_compared_as_text() {
        let earlier_looking = "2015-01-16T13:00:00-05:00";
        let later_looking = "2015-01-16T14:00:00+02:00";
        assert!(
            earlier_looking < later_looking,
            "precondition: lexical order"
        );
        assert!(chronological_key(earlier_looking) > chronological_key(later_looking));
    }

    #[test]
    fn sub_second_precision_differences_are_compared_numerically() {
        assert!(
            chronological_key("2021-06-02T12:14:18.9Z")
                > chronological_key("2021-06-02T12:14:18.028555Z")
        );
    }

    #[test]
    fn an_unparseable_timestamp_sorts_below_every_parseable_one() {
        assert!(chronological_key("not a date") < chronological_key("1970-01-01T00:00:00Z"));
    }

    #[test]
    fn an_empty_timestamp_sorts_below_every_parseable_one() {
        assert!(chronological_key("") < chronological_key("1970-01-01T00:00:00Z"));
    }

    #[test]
    fn two_unparseable_timestamps_compare_equal() {
        assert_eq!(chronological_key("nope"), chronological_key("also nope"));
    }
}
