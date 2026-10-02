# API outline

URLs below are relative to `/share/` in the browser. nginx strips that prefix before forwarding. Responses are JSON unless a file/HTML response is indicated.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `api/items` | List stored shares; protected contents remain locked |
| GET | `api/storage` | Storage usage |
| POST | `api/create` | JSON: text, expiry, password, file_count; returns item ID and upload token |
| POST | `api/upload` | File bytes with item/token/name query parameters; see handler for metadata |
| POST | `api/unlock` | Unlock an item with its password |
| POST | `api/delete` | Delete an item subject to its authorization checks |
| POST | `api/direct/create` | JSON: name, size, mime, sender_name, client_id |
| POST | `api/direct/accept` | JSON: id, receiver_name; returns receiver URL |
| POST | `direct/send/<id>?token=...` | Stream sender bytes |
| GET | `direct/receive/<id>?token=...` | Stream received bytes |
| POST | `api/direct/cancel` | Cancel with sender token |
| POST | `share-target` | Multipart PWA share target; redirects to the UI |

This describes the recovered API, not a versioned compatibility guarantee. Tokens are private; do not publish request URLs or logs containing them.
