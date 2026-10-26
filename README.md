# v2 cloud-only one-shot bridge

Publish only `trial_server.py`, `render_server.py`, `probe_server.py`, and optionally
`test_v2.py`. Start: `python probe_server.py`. Build/test: `python -m unittest test_v2 -v`.
Old prototype directories are unchanged. No account IDs, QQ data, or actual secrets here.

## Configuration
- `TRIAL_EXPIRES_AT`: fixed UTC deadline, at most 900 seconds ahead at startup.
  Missing/expired/far-future deadline closes the service's trial; `/health` stays up.
- `TRIAL_BEARER_SHA256`: lowercase hex SHA256 of the exact ASCII Bearer generated
  locally by Work using 32 cryptographically random bytes (e.g. hex encoded).
  No human passwords. Only the verifier is shared/configured; never the Bearer.
  Missing/malformed verifier closes the trial. Render persists this verifier until
  it is deleted; this is NOT a claim that all authentication material is RAM-only.
- Absolute expiry is not extended by restart or subscription. Deployment consumes
  the window. Do not automatically refresh it. Remove verifier configuration and
  stop/delete the service after the explicitly authorized test.

## Pairing before local arm
1. Current dot subscribes `synthetic.marker_created` and records returned `id`.
2. Confirm that exact subscription ID through the current dot's actual tool result.
   Give only this nonsecret expected ID to Work. Local adapter MUST compare trigger
   and probe subscription_id to this expected value. callback_verified alone is not
   current-dot identity. If mismatch, do not send QQ reply; stop/redeploy explicitly.
3. First verified subscription is pinned; replacement key/URL and unsubscription
   are refused. Anonymous racing subscription can deny service, not obtain the
   properly paired callback's private capability. No OAuth identity claim is made.
4. Work arms only after matching configuration. Marker is exactly 32 ASCII chars
   `[A-Za-z0-9_-]`; confirm this candidate with Work before live use.

## Local HTTP contract
`POST /trigger` and `POST /probe`, JSON exactly `{"marker":"<32 chars>"}`,
`Authorization: Bearer <local-memory secret>`. TLS required by the local client.
No credentials in URL, command arguments, logs, or chat. Invalid auth: HTTP 401;
invalid/unavailable probe: HTTP 409. Local client must fail closed on either.
Trigger returns marker,event_id,subscription_id,expires_at (Unix integer),state=accepted.
Probe returns identical correlation fields, state=pending or acknowledged.
Acknowledged additionally returns ack_source=current_dot and ack_tag=DOT_QQ_ACK.
Expiry freezes at min(service expiry, subscription expiry) when triggered.
Only one marker/process; same marker trigger is idempotent; no automatic event.

## Existing MCP tool schema is preserved
Event name: `synthetic.marker_created`; tools: `synthetic_status`, `synthetic_reply`.
Callback `eventId` remains the public logical event ID. Private callback data contains
marker and `reply_token = eventId + '.' + random_nonce`.
**Call synthetic_reply with event_id set to data.reply_token, NOT callback eventId.**
The existing tool takes only `{event_id: string}`; its schema did not change.
Do not show the reply_token in chat, logs, handoffs, or probe responses.
The server verifies this capability, then returns only public event_id and DOT_QQ_ACK.
All public status surfaces omit event contents; no replay/read API exists.
The `current_dot` label means the manually confirmed, pinned callback capability;
this is not independent platform authentication of the caller.

Tests are loopback/fake callback only and use explicit dummy random values and Bearer.
They do not prove Render deployment, installed event delivery or real QQ receipt.
