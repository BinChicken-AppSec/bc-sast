use super::*;
pub fn build_llm_client(cli: &Cli) -> Result<Arc<dyn LlmClient>, String> {
    build_llm_stack(cli).map(|stack| stack.client)
}

pub(crate) struct LlmStack {
    pub client: Arc<dyn LlmClient>,
    pub settings: llm_settings::TransportSettings,
    pub learned: Option<Arc<appsec_llm_openai::LearnedModels>>,
}

impl LlmStack {
    pub(crate) fn responses_fallbacks(&self) -> Option<u64> {
        self.learned.as_ref().map(|l| l.responses_fallbacks())
    }

    pub(crate) fn resolved_transport(&self, model: &str) -> Option<(&'static str, bool)> {
        let state = self.learned.as_ref()?.transport(model);
        Some((state.endpoint(), state.fell_back()))
    }
}

pub(crate) fn build_llm_stack(cli: &Cli) -> Result<LlmStack, String> {
    let settings = llm_settings::resolve(
        cli.openai_api,
        cli.no_cache_markers,
        &lenient_config_data(cli),
    )?;
    let mut gateway_config = appsec_gateway_http::GatewayConfig::new(cli.gateway_base_url.clone());
    gateway_config.ca_cert_path = cli.ca_cert.clone();
    gateway_config.client_cert_path = cli.client_cert.clone();
    gateway_config.client_key_path = cli.client_key.clone();
    let http = appsec_gateway_http::build_client(&gateway_config).map_err(|e| e.to_string())?;
    let (client, learned): (Arc<dyn LlmClient>, _) = match cli.dialect {
        Dialect::Openai => {
            let learned = Arc::new(appsec_llm_openai::LearnedModels::new());
            let client = appsec_llm_openai::OpenAiClient::new(
                http,
                cli.gateway_base_url.clone(),
                cli.gateway_api_key.clone(),
            )
            .with_api(settings.openai_api)
            .with_learned_models(learned.clone());
            (Arc::new(client), Some(learned))
        }
        Dialect::Anthropic => (
            Arc::new(appsec_llm_anthropic::AnthropicClient::new(
                http,
                cli.gateway_base_url.clone(),
                cli.gateway_api_key.clone(),
            )),
            None,
        ),
    };
    let client: Arc<dyn LlmClient> = Arc::new(appsec_llm_client::ApplyCachePolicy::new(
        client,
        settings.cache,
    ));
    let client = if stream_large_responses(cli) {
        Arc::new(appsec_llm_client::StreamLargeResponses::new(client))
    } else {
        client
    };
    Ok(LlmStack {
        client,
        settings,
        learned,
    })
}

pub(super) fn lenient_config_data(cli: &Cli) -> Value {
    cli.config
        .as_ref()
        .and_then(|path| config_load::load(path).ok())
        .map(|loaded| loaded.data)
        .unwrap_or(Value::Null)
}

pub(super) fn stream_large_responses(cli: &Cli) -> bool {
    if cli.stream_large_responses {
        return true;
    }
    cli.config
        .as_ref()
        .and_then(|path| config_load::load(path).ok())
        .and_then(|loaded| config_overrides::llm_stream_large_responses_override(&loaded.data))
        .unwrap_or(false)
}

pub fn build_github_client(cli: &Cli) -> Result<Option<appsec_github::GithubClient>, String> {
    match (&cli.github_token, &cli.github_repo, cli.pr_number) {
        (Some(token), Some(repo), Some(pr_number)) => {
            let (owner, name) = repo
                .split_once('/')
                .ok_or_else(|| format!("--github-repo must be \"owner/name\", got {repo:?}"))?;
            let mut config =
                appsec_github::GithubConfig::new(owner, name, pr_number, token.clone());
            config.api_base_url = cli.github_api_base_url.clone();
            let http = finish_github_http_client(
                reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)),
            )?;
            Ok(Some(appsec_github::GithubClient::new(http, config)))
        }
        _ => Ok(None),
    }
}

pub(super) fn finish_github_http_client(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::Client, String> {
    builder
        .build()
        .map_err(|e| format!("failed to build GitHub HTTP client: {e}"))
}
