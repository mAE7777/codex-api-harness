# Media alternatives

Reviewed on 2026-10-23. Image/video generation, transcription and speech output remain disabled. No model weights, microphone permissions, cloud media credentials or host service were added. A service available through another agent is not automatically free to this harness.

| Capability | Credible local option | Decision for this release |
|---|---|---|
| Transcription | [whisper.cpp](https://github.com/ggml-org/whisper.cpp), [faster-whisper](https://github.com/SYSTRAN/faster-whisper) | Optional adapter candidate; needs pinned engine/weights, resource limits and explicit file input |
| Speech output | [Kokoro-82M](https://huggingface.co/hexgrad/Kokoro-82M) | Optional candidate; the model card lists Apache-2.0; engine, voices and other dependencies require their own review |
| Images | [ComfyUI](https://github.com/Comfy-Org/ComfyUI) with an explicitly licensed model/workflow | Optional candidate; arbitrary custom nodes execute code and are not a safe default |
| Video | [Wan2.2](https://github.com/Wan-Video/Wan2.2) or a reviewed ComfyUI workflow | Optional candidate; hardware, weight sizes and inference cost make this unsuitable as a default coding dependency |

Local inference avoids a metered media API. It still consumes the user's memory, storage, electricity and time. A CPU/GPU feature advertised by an engine does not establish availability inside this Docker VM. Calling a host GPU service would cross the current host-access boundary and needs a dedicated adapter; the public fetch tool deliberately cannot access localhost services.

## What OpenClaw and Hermes demonstrate

[OpenClaw's ComfyUI integration](https://docs.openclaw.ai/providers/comfy) supports local workflows as well as separate cloud configuration. The local workflow pattern is useful: explicitly select the engine, model and graph rather than silently route to a cloud provider. It does not make remote Comfy or other image/video providers free. Its [speech quickstart](https://docs.openclaw.ai/tools/tts/quickstart) also supports local command providers; an arbitrary command template still requires code review and isolation.

[Hermes tools](https://hermes-agent.nousresearch.com/docs/user-guide/features/tools) includes a Nous Tool Gateway offering search, images, TTS and browser tools to paid Portal subscribers. “No separate API key” therefore does not meet a free-only requirement. [Hermes voice mode](https://hermes-agent.nousresearch.com/docs/user-guide/features/voice-mode) is a useful reference for local transcription and explicit provider selection, rather than evidence that every voice backend is free.

No-key speech endpoints and public demo hosts can be convenient, but their availability, limits, data handling and terms can change. We did not establish a durable, account-independent free media API suitable for automatic enablement here. Trial credits, a provider directory, model weights and a hosted inference service are different things. There is no fallback to a billed account when a free endpoint stops.

## Core versus optional

The core covers coding, project files, local browser testing, bounded public text retrieval and verified search. Media engines belong in optional reviewed adapters. A future media adapter needs exact source/model hashes and licenses, bounded file inputs/outputs, memory/time/storage limits, a closed destination policy, no automatic weight downloads or paid fallback, and native tests on supported hardware. Camera, microphone, browser login and host GPU access each need their own explicit permission decision.

The existing skill-only plugin format cannot grant those capabilities. A skill can explain a workflow; it cannot enable an arbitrary media server or fetch weights through an unreviewed installation script. See [EXTENSIONS.md](EXTENSIONS.md) and [TOOLS.md](TOOLS.md).
