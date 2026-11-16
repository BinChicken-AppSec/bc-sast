use appsec_llm_client::{CachePolicy, CacheTtl, OpenAiApi};
use serde_json::Value;

pub(crate) const DEFAULT_OPENAI_API: OpenAiApi = OpenAiApi::Auto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransportSettings {
    pub openai_api: OpenAiApi,
    pub cache: CachePolicy,
}

pub(crate) fn resolve(
    cli_openai_api: Option<OpenAiApi>,
    no_cache_markers: bool,
    data: &Value,
) -> Result<TransportSettings, String> {
    let llm = data.get("llm").unwrap_or(&Value::Null);
    let openai_api = match cli_openai_api {
        Some(api) => api,
        None => parsed(llm, "openai_api")?.unwrap_or(DEFAULT_OPENAI_API),
    };
    let markers = match llm.get("cache_markers") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(on)) => *on,
        Some(other) => {
            return Err(format!(
                "llm.cache_markers must be true or false, not {other}"
            ))
        }
    };
    let min_block_tokens = match llm.get("cache_min_block_tokens") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    format!(
                        "llm.cache_min_block_tokens must be a positive whole number of \
                         tokens or null, not {value}"
                    )
                })?,
        ),
    };
    let ttl: CacheTtl = parsed(llm, "cache_ttl")?.unwrap_or_default();
    Ok(TransportSettings {
        openai_api,
        cache: CachePolicy {
            markers: markers && !no_cache_markers,
            min_block_tokens,
            ttl,
        },
    })
}

fn parsed<T: std::str::FromStr<Err = String>>(llm: &Value, key: &str) -> Result<Option<T>, String> {
    match llm.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|e| format!("llm.{key}: {e}")),
        Some(other) => Err(format!("llm.{key} must be a string, not {other}")),
    }
}

pub(crate) fn transport_label(
    anthropic: bool,
    client_api: OpenAiApi,
    role_pin: Option<OpenAiApi>,
) -> &'static str {
    if anthropic {
        "messages"
    } else {
        role_pin.unwrap_or(client_api).as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nothing_configured_gives_auto_and_the_library_cache_defaults() {
        let settings = resolve(None, false, &Value::Null).unwrap();
        assert_eq!(settings.openai_api, OpenAiApi::Auto);
        assert_eq!(settings.cache, CachePolicy::default());
        let defaults = appsec_config::step_defaults();
        assert_eq!(resolve(None, false, &defaults).unwrap(), settings);
    }

    #[test]
    fn the_flag_beats_the_config_which_beats_the_default() {
        let data = json!({"llm": {"openai_api": "chat"}});
        assert_eq!(
            resolve(None, false, &data).unwrap().openai_api,
            OpenAiApi::Chat
        );
        assert_eq!(
            resolve(Some(OpenAiApi::Responses), false, &data)
                .unwrap()
                .openai_api,
            OpenAiApi::Responses
        );
    }

    #[test]
    fn every_cache_key_is_read() {
        let data = json!({"llm": {
            "cache_markers": false, "cache_min_block_tokens": 2048, "cache_ttl": "1h",
        }});
        let cache = resolve(None, false, &data).unwrap().cache;
        assert_eq!(
            cache,
            CachePolicy {
                markers: false,
                min_block_tokens: Some(2048),
                ttl: CacheTtl::OneHour,
            }
        );
    }

    #[test]
    fn no_cache_markers_only_ever_turns_markers_off() {
        let on = json!({"llm": {"cache_markers": true}});
        assert!(!resolve(None, true, &on).unwrap().cache.markers);
        let off = json!({"llm": {"cache_markers": false}});
        assert!(!resolve(None, false, &off).unwrap().cache.markers);
    }

    #[test]
    fn malformed_values_fail_naming_the_key() {
        let cases = [
            (json!({"llm": {"openai_api": "grpc"}}), "llm.openai_api: "),
            (
                json!({"llm": {"openai_api": 1}}),
                "llm.openai_api must be a string",
            ),
            (json!({"llm": {"cache_ttl": "1hr"}}), "llm.cache_ttl: "),
            (
                json!({"llm": {"cache_markers": "on"}}),
                "llm.cache_markers must be",
            ),
            (
                json!({"llm": {"cache_min_block_tokens": 0}}),
                "llm.cache_min_block_tokens must be",
            ),
            (
                json!({"llm": {"cache_min_block_tokens": "1024"}}),
                "llm.cache_min_block_tokens must be",
            ),
            (
                json!({"llm": {"cache_min_block_tokens": 5_000_000_000u64}}),
                "llm.cache_min_block_tokens must be",
            ),
        ];
        for (data, want) in cases {
            let err = resolve(None, false, &data).unwrap_err();
            assert!(err.starts_with(want), "{err} for {data}");
        }
    }

    #[test]
    fn a_null_leaves_each_key_at_its_default() {
        let data = json!({"llm": {
            "openai_api": null, "cache_markers": null,
            "cache_min_block_tokens": null, "cache_ttl": null,
        }});
        assert_eq!(
            resolve(None, false, &data).unwrap(),
            resolve(None, false, &Value::Null).unwrap()
        );
    }

    #[test]
    fn the_transport_label_prefers_the_role_pin_and_names_anthropic_messages() {
        assert_eq!(transport_label(false, OpenAiApi::Auto, None), "auto");
        assert_eq!(
            transport_label(false, OpenAiApi::Auto, Some(OpenAiApi::Chat)),
            "chat"
        );
        assert_eq!(
            transport_label(true, OpenAiApi::Auto, Some(OpenAiApi::Chat)),
            "messages"
        );
    }
}
