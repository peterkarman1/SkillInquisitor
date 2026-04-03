# Single-Container CLI Image Design

## Goal

Package SkillInquisitor as self-contained container images that preserve the existing CLI UX while eliminating the current nested-container fallback for `llama-server`.

The user experience should look like:

```bash
docker run --rm -it \
  --mount type=bind,src="$PWD",dst=/workspace \
  -w /workspace \
  skillinquisitor:tiny-cpu \
  scan path/to/skill
```

The same subcommands should work for the CPU and GPU images because the image entrypoint will be the existing `skillinquisitor` CLI.

## Problem Statement

Today the application runs as a host Python CLI. The LLM layer prefers a native `llama-server` binary, but if that binary is missing it falls back to launching Docker containers for `llama.cpp` server execution. That creates an awkward operational model:

- the scanner itself may run on the host
- LLM inference may run in separate nested containers
- host dependencies like `repomix`, model caches, and Docker daemon access have to line up correctly

We want one image that already contains the scanner, the inference runtime, and all required models so runtime behavior is deterministic and self-contained.

## Design Summary

Ship two container images:

- `skillinquisitor:tiny-cpu`
- `skillinquisitor:tiny-cuda`

Both images will:

- expose the existing CLI through `ENTRYPOINT ["skillinquisitor"]`
- contain a real `llama-server` binary on `PATH`
- contain `repomix` on `PATH`
- contain `git` for remote-target cloning
- contain the SkillInquisitor Python application and dependencies
- contain all required LLM and ML models inside the image

The difference between the two images is only the inference runtime base and the target deployment environment:

- `tiny-cpu` is the default portable image and is the expected image for macOS or generic Linux hosts
- `tiny-cuda` is the Linux/NVIDIA image and is meant to be run with GPU access enabled

## Required Baked-In Models

### LLM Models

Bake in the current `tiny` model group:

- `unsloth/Qwen3.5-0.8B-GGUF`
- `unsloth/Llama-3.2-1B-Instruct-GGUF`
- `bartowski/gemma-2-2b-it-GGUF`
- `unsloth/Qwen3.5-2B-GGUF`

These should be stored at the application's normal cache location so the existing runtime resolves them without special-case code.

### ML Models

Bake in the current prompt-injection ensemble models:

- `protectai/deberta-v3-base-prompt-injection-v2`
- `patronus-studio/wolf-defender-prompt-injection`
- `madhurjindal/Jailbreak-Detector`

These should also live in the normal cache structure so the existing ML download/load path becomes a cache hit at runtime.

## Runtime Behavior

No new serving architecture is required.

The existing runtime already starts `llama-server` as a subprocess, waits for its health endpoint, and sends requests to its local OpenAI-compatible HTTP endpoint. Once the image contains a real `llama-server` binary, the current code path will use that binary directly and will no longer need to fall back to `docker run ...`.

That means the runtime flow inside the image stays simple:

1. user invokes `docker run ... skillinquisitor:<tag> scan ...`
2. the Python CLI starts inside the container
3. the LLM layer launches `llama-server` as a subprocess in the same container
4. the scanner communicates with `127.0.0.1:<ephemeral-port>`
5. the subprocess exits according to the current lifecycle rules

This keeps the implementation aligned with the current codebase and avoids introducing a second process supervisor or a fixed in-container inference daemon.

## Image Configuration

The images should carry an image-local SkillInquisitor config file that pins the intended behavior:

```yaml
layers:
  llm:
    default_group: tiny
    auto_select_group: false
    auto_download: false
  ml:
    auto_download: false
```

This ensures runtime never tries to download missing models and never auto-switches to the `balanced` group.

The config should be applied by default inside the image rather than relying on environment-variable overrides, because the normal CLI scan path currently does not pass the host environment into config loading.

## Build Strategy

### Common Build Responsibilities

Each image build must:

1. install the Python application and its runtime dependencies
2. install `git`
3. install Node/npm and `repomix`
4. install or copy in a working `llama-server` binary
5. run the existing model-download commands during the image build
6. leave all downloaded assets in the final image

### CPU Image

The CPU image should prioritize portability over acceleration.

Characteristics:

- works on generic Linux hosts
- works as the default image for local macOS Docker use
- runs the baked-in tiny model group with CPU execution

### CUDA Image

The CUDA image should target Linux hosts with NVIDIA GPUs.

Characteristics:

- ships the same scanner and same baked-in model set
- ships a GPU-capable `llama-server`
- is meant to be launched with GPU access, for example `--gpus all`

The two-image approach is preferable to trying to hide CPU/GPU behavior behind a single tag, because it keeps runtime expectations explicit and packaging simpler.

## CLI UX

The container should preserve the existing CLI contract:

```bash
docker run --rm -it \
  --mount type=bind,src="$PWD",dst=/workspace \
  -w /workspace \
  skillinquisitor:tiny-cpu \
  scan tests/fixtures/local/basic-skill
```

Other commands should work the same way:

```bash
docker run --rm skillinquisitor:tiny-cpu models list
docker run --rm skillinquisitor:tiny-cpu rules list
docker run --rm skillinquisitor:tiny-cpu benchmark run --tier smoke
```

Remote Git scan targets should also work because the image contains `git`.

## Filesystem Expectations

The default runtime path should assume:

- source repositories are bind-mounted into `/workspace`
- the current working directory is `/workspace`

Since the models are baked into the image, no host model-cache mount is required.

## Non-Goals

This design does not include:

- a long-lived separate inference service inside the container
- baking in the `balanced` model group
- retaining runtime model downloads
- supporting Apple MPS acceleration inside Docker
- changing the scanner's inference protocol away from local `llama-server`

## Risks And Tradeoffs

### Image Size

Baking in both the tiny GGUF set and all ML models will produce large images. This is an intentional tradeoff in exchange for deterministic startup and zero runtime downloads.

### Build Time

Image builds will be slower because they have to download all models during the build.

### CPU Performance

The CPU image is the compatibility image, not the high-throughput image. It should be expected to work everywhere, not to be fast everywhere.

### Platform Split

The GPU image should be documented as Linux/NVIDIA-specific. The CPU image should remain the default documented path for local macOS use.

## Recommended Implementation Direction

Implement this in three layers:

1. add image build assets and image-local config
2. make the CLI container-friendly by default
3. update docs to treat the container images as first-class distribution targets

## Acceptance Criteria

The work is complete when all of the following are true:

- `docker run ... skillinquisitor:tiny-cpu scan ...` works with the same subcommands as the host CLI
- no nested `docker run` fallback is required during LLM analysis inside the image
- no runtime model downloads occur in either image
- both the LLM tiny group and the ML prompt-injection ensemble are available in the image at startup
- `tiny-cuda` is documented and buildable for Linux/NVIDIA environments
- README documents the new container-first workflow clearly
