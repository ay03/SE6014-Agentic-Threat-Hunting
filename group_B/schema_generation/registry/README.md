# B2 schema registry

This directory is the default location for validated B2 schema entries. The
runtime layout is:

```text
registry/
  index.json
  schemas/<schema_id>/v<version>.json
```

Each entry stores the declarative `SchemaSpec`, the compiled Elasticsearch
ingest pipeline, the pipeline ID, the validation report and provenance. The
index maps a structural source signature hash to the latest registered entry
for that signature.

Only schemas with an accepted validation report can be registered. Entry and
index writes use a temporary file followed by `os.replace`. The registry
assumes a single writer; the Batch 4 CLI should serialize writes if it runs
concurrently.
