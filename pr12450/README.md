# #12450: CLI Quickstart evidence

## Revisions and validation

- Implementation exercised: `800a86be67269d46c7a8a46da3f2b033ad61132b`.
- Built from the clean PR worktree with `CARGO_BUILD_JOBS=4 RUSTC_WRAPPER= cargo build --offline --locked -p zeroclaw --bin zeroclaw` (exit 0).
- Binary SHA-256: `408921eec437f08c104294d6f31131991c223c14cc64052d06b85a4e7058f7a0`.
- Real tmux PTY: 160 columns × 50 rows, `en_US.UTF-8`. Pane captures are direct terminal output. Screenshots show the same real terminal panes in xterm on an isolated Xvfb display; the interface was not reconstructed.
- [Current-head Quality Gate](https://github.com/zeroclaw-labs/zeroclaw/actions/runs/44936965439) supplies the workspace/platform test evidence. This manual run supplements it rather than rerunning that suite.
- Build warnings about the unused `zeroclaw-dist` workspace dependency and `Atomic::fetch_update` are also present on master; no dependency or unrelated warning cleanup is included here.

## Fresh connection/model creation

On an isolated initially empty V5 configuration, run the built binary:

```sh
zeroclaw quickstart --config-dir <isolated-dir> \
  --model-provider openai --model gpt-synthetic-fresh \
  --api-key <synthetic-placeholder> --agent evidence_fresh
```

Choose Balanced risk, no memory, no channels, then Create. Actual output:

- [Prefilled form](fresh-prefilled.txt)
- [Ready-to-create checklist](fresh-ready.txt)
- [Completion output](fresh-complete.txt)
- [Actual terminal screenshot](fresh-complete.png)

The saved TOML was parsed with Python `tomllib`, rather than splitting dotted names. Assertions confirmed `schema_version = 5`, the literal connection and model key `openai.default`, `model = "gpt-synthetic-fresh"`, the agent reference to that model, and the synthetic credential encrypted on disk. The configuration, credential, and encryption key are excluded from this branch.

## Reuse an existing model

Run Quickstart again against that same isolated configuration:

```sh
zeroclaw quickstart --config-dir <isolated-dir> --agent evidence_existing
```

Open Model provider → Use existing → `openai.default`, then fill the remaining selectors and Create.

- [Existing-model picker](existing-picker.txt)
- [Selected model in the checklist](existing-selected.txt)
- [Ready-to-create checklist](existing-ready.txt)
- [Completion output](existing-complete.txt)
- [Actual terminal screenshot](existing-complete.png)

Both agents were actually created. Independent TOML assertions confirmed that `evidence_existing.model_provider` references `openai.default` and that the registry still contains exactly one connection and one model. This proves reuse rather than duplicate creation. No provider inference request was made.

[Machine-readable observations](observations.json) record the source revision, binary hash, dimensions, and assertions.

## Previously reviewed revision

[The original record requested in the review](reviewed-head-6fe2985212.txt) is also public. It explicitly names `6fe2985212728254b90d9b807a9040b5db92095d`, the revision Audacity88 reviewed. Its existing-model flow stopped after selection; the new current-head run above completes both creation flows. Neither record is presented as evidence for another revision.
