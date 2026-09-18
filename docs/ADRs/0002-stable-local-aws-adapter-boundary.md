# ADR 0002: stable local/AWS adapter boundary

**Status:** Accepted

Domain code depends on adapter protocols, not AWS SDK calls. The local adapter
is the initial implementation; an AWS adapter can be introduced without
changing normalized findings or workflow semantics. `FIRST_COMMIT_MODE` selects
the adapter explicitly.

