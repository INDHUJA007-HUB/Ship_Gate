# ADR 0014: Lambda artifacts are built in the runtime's container image

**Status:** Accepted

`infra/template.yaml` pins `Runtime: python3.12`, and `requirements.txt` carries the Lambda
dependency manifest, because the stable SAM builder does not read `pyproject.toml`. A native
`sam build` installs dependencies with the *host* interpreter, so on a machine whose Python is
newer or whose platform differs from Lambda, the artifact silently contains the wrong binaries:
on this host the local virtual environment holds `_internal.cp313-win_amd64.pyd`, which a
`python3.12` x86_64 Lambda cannot import. Loosening the runtime pin to match a developer's Python
would trade a deployment bug for convenience, so the build moves to the runtime instead.

**Decision.**

1. Every `AWS::Serverless::Function` declares `Metadata: {BuildMethod: python3.12}`, matching the
   `Globals.Function.Runtime` value. A guard test fails if a function's build method and runtime
   ever disagree, or if the runtime pin itself changes.
2. Builds that are meant to produce a deployable artifact use SAM's official runtime image:
   `sam build --use-container`, which resolved to `public.ecr.aws/sam/build-python3.12:latest-x86_64`
   on this host.
3. The build runs from a *clean tree* (a checkout, or a copy of tracked files). SAM copies the
   whole `CodeUri` tree into the container, and a working copy also contains `.venv/`, `.tools/`
   and other ignored directories; building in place copies tens of thousands of files and turns a
   two-minute build into an indefinite one. `.aws-sam/` is now ignored for the same reason.
4. `requirements.txt` must cover every runtime and provider dependency declared in
   `pyproject.toml`. A guard test compares the two manifests, which is how a missing
   `strands-agents` entry was found: the artifact built, installed and imported `api.handlers`
   fine, and only failed when the orchestration code imported `strands` at run time.
5. The artifact is verified by importing it with the real runtime image
   (`public.ecr.aws/lambda/python:3.12`), not by inspecting a file listing.

**Consequences.** The verified artifact contains only `cpython-312-x86_64-linux-gnu` extension
modules, no Windows or cp313 binaries, and imports `api.handlers`, the orchestration pipeline and
`strands` on Python 3.12.14. `sam validate --lint` still only proves template shape; packaging the
external scanner binaries into the detect function remains a separate, undeployed proof.
