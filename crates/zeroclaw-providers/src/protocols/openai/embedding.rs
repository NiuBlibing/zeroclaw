//! OpenAI-compatible embeddings wire protocol, shared by vendor adapters.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub(crate) struct EmbeddingRequest<'a> {
    pub(crate) model: &'a str,
    pub(crate) input: &'a [&'a str],
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingItem>,
}
#[derive(Deserialize)]
struct EmbeddingItem {
    index: usize,
    embedding: Vec<f32>,
}

pub(crate) async fn vectors(
    response: reqwest::Response,
    count: usize,
    dimensions: Option<usize>,
) -> Result<Vec<Vec<f32>>> {
    if !response.status().is_success() {
        let status = response.status();
        let body = crate::protocols::error_body(response).await;
        anyhow::bail!("Embedding API returned HTTP {status}: {body}");
    }
    let response: EmbeddingResponse = response
        .json()
        .await
        .context("decoding embedding response")?;
    ensure!(
        response.data.len() == count,
        "embedding response count differs from input count"
    );
    let mut vectors = vec![None; count];
    for item in response.data {
        ensure!(item.index < count, "embedding response index out of range");
        if let Some(dimensions) = dimensions {
            ensure!(
                item.embedding.len() == dimensions,
                "embedding response dimensions differ from configured dimensions"
            );
        }
        ensure!(
            item.embedding.iter().all(|value| value.is_finite()),
            "non-finite embedding component"
        );
        ensure!(
            vectors[item.index].replace(item.embedding).is_none(),
            "duplicate embedding response index"
        );
    }
    vectors
        .into_iter()
        .map(|vector| vector.context("missing embedding response index"))
        .collect()
}
