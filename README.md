# voidnote — Official Zig SDK

Zero-knowledge self-destructing notes and live encrypted streams.
The key lives in the link. We never see it.

**https://voidnote.net**

---

## Install

Add `voidnote.zig` to your project and import it as a module:

```zig
// build.zig
const voidnote = b.addModule("voidnote", .{
    .root_source_file = b.path("path/to/voidnote.zig"),
});
exe.root_module.addImport("voidnote", voidnote);
```

Or, if using the repo as a dependency:

```sh
# build.zig.zon
.dependencies = .{
    .voidnote = .{
        .url = "https://github.com/quantum-encoding/voidnote-zig/archive/main.tar.gz",
    },
},
```

---

## Quick start

### Read a note

```zig
const voidnote = @import("voidnote");

const result = try voidnote.read(allocator, "https://voidnote.net/note/<token>");
defer result.deinit(allocator);

std.debug.print("{s}\n", .{result.content});
std.debug.print("views: {d}/{d}\n", .{ result.view_count, result.max_views });
std.debug.print("destroyed: {}\n", .{result.destroyed});
```

### Create a note

```zig
const result = try voidnote.create(allocator, "launch codes: 4-8-15-16-23-42", .{
    .api_key = "vn_...",
    .max_views = 1,
});
defer result.deinit(allocator);

std.debug.print("share: {s}\n", .{result.url});
std.debug.print("expires: {s}\n", .{result.expires_at});
```

### Live encrypted stream

```zig
var stream = try voidnote.createStream(allocator, .{ .api_key = "vn_..." });
defer stream.deinit();

std.debug.print("share: {s}\n", .{stream.url});

try stream.write("Starting deployment...");
try stream.write("Build complete.");
try stream.write("Service is live.");
try stream.close();
```

### Watch a stream (SSE)

```zig
fn onMessage(msg: []const u8) void {
    std.debug.print(">> {s}\n", .{msg});
}

try stream.watch(allocator, onMessage);
// blocks until stream is closed or connection dropped; auto-reconnects
```

---

## API reference

### `read(allocator, url_or_token) !ReadResult`

Reads a note. Accepts either a full URL or a raw 64-character hex token.

**`ReadResult`** — call `result.deinit(allocator)` when done

| Field | Type | Description |
|-------|------|-------------|
| `content` | `[]const u8` | Decrypted plaintext (owned) |
| `title` | `?[]const u8` | Note title if set (owned) |
| `view_count` | `u32` | How many times read |
| `max_views` | `u32` | Destruction threshold |
| `destroyed` | `bool` | Whether the note is gone |

---

### `create(allocator, content, opts) !CreateResult`

Creates a self-destructing encrypted note.

**`CreateOptions`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | `[]const u8` | required | Your VoidNote API key |
| `title` | `?[]const u8` | `null` | Optional title (stored encrypted) |
| `max_views` | `?u32` | `null` | Destroy after N reads |
| `ttl_minutes` | `?u32` | `null` | Expire after N minutes |

**`CreateResult`** — call `result.deinit(allocator)` when done

| Field | Type | Description |
|-------|------|-------------|
| `url` | `[]const u8` | Shareable URL (key in fragment) |
| `expires_at` | `[]const u8` | ISO 8601 expiry timestamp |

---

### `createStream(allocator, opts) !StreamHandle`

Opens a live encrypted stream.

**`StreamOptions`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | `[]const u8` | required | Your VoidNote API key |
| `title` | `?[]const u8` | `null` | Stream title |
| `max_views` | `?u32` | `null` | Limit concurrent watchers |
| `ttl_minutes` | `?u32` | `null` | Auto-close after N minutes |

**`StreamHandle`** — call `stream.deinit()` when done

| Field/Method | Description |
|-------------|-------------|
| `.url` | Shareable URL for the stream |
| `write(content) !void` | Encrypt and send a message |
| `close() !void` | Close the stream |
| `watch(allocator, callback) !void` | Subscribe via SSE (blocking, auto-reconnects) |

---

## Errors

```zig
const result = voidnote.read(allocator, token) catch |err| switch (err) {
    error.NotFound       => ..., // 404 — gone or never existed
    error.Unauthorized   => ..., // 401 — invalid API key
    error.DecryptFailed  => ..., // tampered content or wrong key
    error.InvalidToken   => ..., // malformed token string
    error.NetworkError   => ..., // HTTP transport failure
    else                 => return err,
};
```

---

## Security model

VoidNote uses **zero-knowledge encryption** — the server never sees your plaintext.

1. A random 32-byte token is generated client-side
2. The first 16 bytes become the `tokenId` (server lookup key only)
3. The last 16 bytes become the `secret` — SHA-256 hashed to derive an AES-256-GCM key
4. Content is encrypted locally before upload
5. The full 64-char hex token is embedded in the URL **fragment** (`#token`) — never sent to the server
6. Anyone with the link can decrypt; without the link, decryption is infeasible

---

## Platform support

The SDK uses platform-specific secure random number generation:

| Platform | Method |
|----------|--------|
| macOS / BSD | `arc4random_buf` |
| Linux | `getrandom` syscall |
| Windows | `BCryptGenRandom` |

No external dependencies. Pure Zig stdlib + HTTP.

---

## Build and run the example

```sh
git clone https://github.com/quantum-encoding/voidnote-zig
cd voidnote-zig

# Read a note
zig build run -- read <url-or-token>

# Create a note
zig build run -- create "my secret" vn_...

# Open a stream
zig build run -- stream vn_...

# Run tests
zig build test
```

---

## Zig version

Tested with **Zig 0.14** (stable). No nightly features required.

---

## License

MIT
