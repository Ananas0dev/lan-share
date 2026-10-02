# Known limitations

- Android/WhatsApp share-sheet testing opened the PWA but sent only a title on the tested combination. Manual multipart uploads worked. A native Android share bridge was discussed but is not implemented here.
- The PWA service worker is minimal and does not make the application fully offline.
- Some English labels remain in Arabic mode. Changes should target the correct language branch.
- Direct transfers disappear on restart; their roughly 2 MiB payload queue is not a total process-memory measurement or a global concurrency limit.
- Python's `cgi` multipart implementation is legacy. Python 3.13+ needs the pinned compatibility package; a maintained streaming parser is a future task.
- The browser and proxy can affect streaming behavior. Direct Send is an application-level relay, not an end-to-end encrypted peer-to-peer channel.
- The original service can log BrokenPipe errors when a client disconnects. That is separate from a share-sheet request omitting its file payload.
