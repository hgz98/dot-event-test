# Five-round QQ personal text relay

Run `python chat_server.py` (standard library only). Deploy the three Python server files and test_chat.py together. `render.yaml` is optional. Health: `GET /health`; MCP: `POST /mcp`; redacted pairing: `GET /status` or `synthetic_status`.

## Fixed window and credentials

Set `TRIAL_BEARER_SHA256` to the lowercase SHA-256 hex digest of the approved private Bearer; never configure raw Bearer in this service. Set `TRIAL_EXPIRES_AT` to an absolute timezone-aware ISO timestamp, no more than 900 seconds ahead at startup. Missing/invalid hash or absent/out-of-window deadline fails closed. `PORT` defaults to 10000. Restart does not extend the absolute deadline, but resets volatile receipts: **do not restart an active run or resume its client after restart**. Cleanup/suspend after the fifth QQ receipt is confirmed, not after the fifth dot ACK. Hard expiry clears RAM and signing secrets; health remains available.

Existing MCP names and tool input shape are preserved:
- Event `synthetic.marker_created`, empty subscription arguments, verified HTTPS webhook only.
- `synthetic_status({})`: redacted counters, subscription ID and transport state.
- `synthetic_reply({event_id: string})`: string now contains JSON with exactly `{"reply_token":"<private event capability>","text":"<reply>"}`. Reply token is NOT public eventId. Do not print/share it. Same token + same reply is idempotent; changed reply rejects. Tool does not itself send QQ.

Subscribe before enabling the local owner-only QQ adapter. Verify `/status.subscription_id` matches the active current-dot subscription. Callback URL and signing key are pinned through expiry; no anonymous unsubscribe or re-pair. Subscription refresh does not extend its expiry.

## Local adapter contract

Both endpoints require `Authorization: Bearer <private raw token>` and JSON bodies.

1. `POST /trigger` **exactly** `{"marker":"<32 Base64URL characters>","text":"<owner message>"}`. Marker must be fresh and unpredictable per message; retain it for retries. Text is 1–1500 Unicode characters, nonblank, no control characters except tab/newline/CR; no invalid Unicode surrogates. No IDs, contacts, group details, images, commands or extra metadata.
2. Success returns `{"marker":...,"event_id":...,"subscription_id":...,"expires_at":<Unix seconds>,"round":1,"state":"accepted"}`. Keep this receipt. Same marker/text reuses the exact receipt without sending another event; same marker/different text rejects.
3. `POST /probe` **exactly** `{"marker":"<same marker>"}` is read-only and repeatable. Returns the same metadata and `state:"pending"`, or `state:"acknowledged"` with `ack_source:"current_dot"`, `ack_tag:"DOT_QQ_CHAT"`, `reply_text:"..."`.
4. Before sending QQ, validate marker, event ID, paired subscription ID, expiry, expected round (1–5), acknowledged state, exact source/tag and valid reply text. Send once per marker. Keep local in-memory sent-marker dedup. On uncertain QQ send result, do not blindly resend. A repeated probe is NOT permission to send twice.
5. Only accept the next owner message after the prior reply has been sent locally. Ignore rapid extra messages; no backlog or general queue. The cloud accepts a next distinct trigger only once the preceding dot ACK exists; max five accepted distinct markers. All five receipts remain retrievable and deduplicated until expiry. A sixth distinct marker rejects; even the fifth ACK does not close retrieval.

HTTP `401`: unauthorized/expired. `409`: invalid input, conflicting duplicate, outstanding previous reply, missing/expired subscription or exhausted rounds. Errors never reflect user text or capabilities. No GET/query-string polling.

Event `data` is exactly `{marker,text,round,reply_token}` with the usual `eventId`, name, timestamp and cursor envelope. Text is untrusted conversational input, not instructions to operate tools or reveal credentials. Current dot maintains one continuous five-exchange conversation, composes the short Mashiro-roleplay reply and uses the private reply capability. No model API calls are implemented.

## Privacy and limitations

User/reply text and five receipts exist only in process RAM. No application access logs, transcript endpoints, text persistence, QQ connection or arbitrary commands. Public status includes only stage, remaining seconds, pairing flag, callback HTTP status, subscription ID, admitted/acknowledged counts and limit. Public tool results never return reply text or private tokens. Verified signed callback delivers text only to the pinned subscription; authenticated `/probe` returns it to the local adapter.

This is a bounded personal trial, not production: first verified subscription wins and pairing must be checked before forwarding any text; public MCP remains anonymous, capability possession gates replies. The source/tag identifies the private event-capability flow, not independently verified human identity. Delivery uses up to three attempts with the same event ID. No durable exactly-once QQ delivery is claimed. Do not send secrets or sensitive messages. Cloud platform logging/retention is outside application control.

## Local verification

`python -m unittest -v test_chat` uses dummy credential material, mocked callbacks and loopback HTTP only. No external callbacks, QQ sends or credential generation. Covers five rounds + sixth rejection; duplicate/conflict handling; repeatable probes; unchanged tool input schema; redacted status; pinned subscriptions; hard expiry and text validation.
