The committed `models.dev.json` is the build-time catalogue baseline.
Runtime `tokn-router update` can replace it with a cached catalogue after restart.

On 2026-09-03, `reasoning_options` was imported from
https://models.dev/api.json for 123 exact provider/model matches in this snapshot.
Other fields and model identities were retained. Unmatched records have unknown
effort support; they do not inherit effort levels from another provider or model.

The options are provider-specific: DeepSeek V4 Flash advertises `low`, `high`,
and `max`; DeepSeek V4 Pro advertises `high` and `max`.
