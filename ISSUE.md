# Issues

Known issues and possible improvements we may need to address later, numbered in the order
they were added.
When an issue is fixed, remove it here and mention it in the commit message.

---

## 1. Anthropic tool loops break because signed reasoning is removed

**Status:** open, does not affect the current public model (`openai/gpt-5-mini`).

The gateway removes `reasoning.encrypted` items and `signature` fields from `reasoning_details`
before classification (see README, *Opaque reasoning*). Anthropic models require the signed
thinking blocks to be sent back during a tool-calling loop; without them the provider returns
an error. Plain chat keeps working.

**Possible fix:** remember a hash of every opaque blob the gateway relayed *from* the public
provider (Redis, per session, with TTL). Allow a replayed blob through only when its hash is
known and the request routes public; drop it otherwise. That keeps the "nothing unclassified
from the client" rule, because the gateway itself saw the blob come from the provider.

## 2. Other opaque reasoning formats are not removed

**Status:** open, fail-safe (routes local, no leak).

Only the OpenRouter chat-completions format (`messages[].reasoning_details`) is handled.
Other formats would still be classified as text and can push harmless follow-ups to local:
OpenAI Responses API `encrypted_content`, Anthropic native `redacted_thinking` / `thinking`
content parts with `signature`. Add them when a client actually sends them.

## 3. IBAN detector: registry table and glued IBANs

**Status:** open, by design.

The `iban` rule now requires the exact length for the country (`IBAN_LENGTHS` in
`detectors.py`, from the SWIFT registry) and rejects candidates glued to letters, digits,
`+` or `=`. This dropped false hits on random base64 from about 17% per 3.7 kB blob to 0 in
20,000 tries. Trade-offs:

- New registry countries are not detected until the table is updated.
- An IBAN glued to a following word (`NL91ABNA0417164300please`) is not detected.

## 4. Calibration set does not discriminate around the thresholds

**Status:** open.

Every `public_min_prob` from 0.5 to 0.9 gives 0 leaks and all public examples released
(75 examples). Nearly all examples are clear-cut; there are no hard sensitive cases near the
threshold. The thresholds are therefore not really calibrated. Add borderline examples from
real traffic, both public and sensitive, and rerun the sweep. Note that the earlier
borderline follow-ups (p_public 0.79-0.80) were caused by the opaque reasoning blob (issue
fixed), not by the conversation itself.

## 6. Config reload fails after an editor replaces `config.yaml`

**Status:** open.

`compose.yml` bind-mounts the single file `./config.yaml`. Tools that save by writing a new
file and renaming it (`sed -i`, some editors) give the file a new inode; the container keeps
the old, deleted one and SIGHUP reload fails with `FileNotFoundError`. Workaround:
`docker compose restart gateway`. Fix: mount the directory (for example `./deploy/` →
`/etc/privacy-gateway/`) instead of the single file.

## 7. Open WebUI sends built-in tool schemas with every chat request

**Status:** open, harmless.

Open WebUI adds the tools `get_current_timestamp` and `calculate_timestamp` to each request.
They are classified (small effect on the score) and forwarded to the provider. If it matters,
the pipe could drop `tools` that only contain Open WebUI built-ins, or the built-in tools can
be switched off in Open WebUI.

## 8. Open WebUI pipe models are visible to admins only

**Status:** open, only relevant with non-admin users.

Pipe models without a model entry are shown to admins only. Give users access under
*Admin Panel → Settings → Models* (`auto`, `local`), or let `openwebui/install.py` create the
model entries with access grants.

## 9. Option to not classify earlier assistant answers

**Status:** idea, not built. Today every follow-up classifies the whole request, including
earlier assistant answers, the system prompt and tool content.

**Why:** public answers sent back as history can still affect the score of a harmless follow-up.

**Rejected as-is: "only check user messages".** Everything not checked is still forwarded, so
a sensitive local answer (or RAG content in the system prompt, or tool results) would reach the
public provider on a harmless follow-up. The sticky pin does not close this, because many local
routes do not pin: uncertain results when `sticky_on_uncertain: false`, classifier errors, model
`local`, and pins expire after the TTL or vanish when Redis restarts (no persistence). API
clients can also write their own "assistant" messages.

**Design options:**

1. **Skip verified public answers (preferred).** Store a hash of every assistant answer the
   gateway relayed from the public provider (Redis, per session, same TTL as pins). On a
   follow-up, exclude assistant messages whose hash is known: they came from outside, sending
   them back reveals nothing new. Local answers, edited or unknown answers, user, system and
   tool content are still classified. Redis unavailable → classify as today. Streaming
   answers are assembled to compute the hash. Same mechanism can solve issue 1.
2. **User-only mode with safeguards.** Config option to skip assistant messages; in that mode
   every local route pins the chat (also uncertain, errors and model `local`), and system and
   tool content are still classified. Remaining risks: pin expiry / Redis loss, and API
   clients writing assistant messages. Must be documented as less strict.
