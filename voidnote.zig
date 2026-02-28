//! VoidNote — Official Zig SDK
//!
//! Zero-knowledge self-destructing notes and live encrypted streams.
//! The key lives in the link. We never see it.
//!
//! https://voidnote.net
//!
//! Usage:
//!   const voidnote = @import("voidnote");
//!
//!   // Read a note
//!   const result = try voidnote.read(allocator, "https://voidnote.net/note/<token>");
//!   defer result.deinit(allocator);
//!   std.debug.print("{s}\n", .{result.content});
//!
//!   // Create a note
//!   const note = try voidnote.create(allocator, "my secret", .{ .api_key = "vn_..." });
//!   defer note.deinit(allocator);
//!   std.debug.print("share: {s}\n", .{note.url});
//!
//!   // Live stream
//!   var stream = try voidnote.createStream(allocator, .{ .api_key = "vn_..." });
//!   defer stream.deinit();
//!   try stream.write("Deployment starting...");
//!   try stream.close();

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

// ── Crypto ────────────────────────────────────────────────────────────────────

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const default_base = "https://voidnote.net";

// ── Error ─────────────────────────────────────────────────────────────────────

pub const VoidNoteError = error{
    /// Token is not a valid 64-char hex string
    InvalidToken,
    /// HTTP request failed at the transport level
    NetworkError,
    /// Server returned a non-2xx status
    HttpError,
    /// JSON response could not be parsed
    JsonParseError,
    /// AES-GCM tag verification failed (wrong key or tampered data)
    DecryptionFailed,
    /// Hex string contains invalid characters or odd length
    InvalidHex,
    /// API key is required but was not provided
    MissingApiKey,
    OutOfMemory,
};

// ── Types ─────────────────────────────────────────────────────────────────────

pub const ReadResult = struct {
    content: []const u8,
    title: ?[]const u8,
    view_count: u32,
    max_views: u32,
    /// true if the note was destroyed after this read (view limit reached)
    destroyed: bool,

    pub fn deinit(self: ReadResult, allocator: Allocator) void {
        allocator.free(self.content);
        if (self.title) |t| allocator.free(t);
    }
};

pub const CreateOptions = struct {
    api_key: []const u8,
    title: ?[]const u8 = null,
    max_views: u8 = 1, // 1–100
    expires_in: u16 = 24, // hours: 1, 6, 24, 72, 168, 720
    note_type: []const u8 = "secure", // "secure" or "pipe"
    base: []const u8 = default_base,
};

pub const CreateResult = struct {
    url: []const u8,
    expires_at: []const u8,

    pub fn deinit(self: CreateResult, allocator: Allocator) void {
        allocator.free(self.url);
        allocator.free(self.expires_at);
    }
};

pub const StreamOptions = struct {
    api_key: []const u8,
    title: ?[]const u8 = null,
    ttl: u32 = 3600, // 3600 | 21600 | 86400
    base: []const u8 = default_base,
};

pub const StreamHandle = struct {
    /// Shareable URL containing the decryption key
    url: []const u8,
    expires_at: []const u8,
    full_token: [64]u8,
    secret: [32]u8, // hex chars of token[32..64]
    base: []const u8,
    allocator: Allocator,

    pub fn deinit(self: StreamHandle) void {
        self.allocator.free(self.url);
        self.allocator.free(self.expires_at);
        if (self.base.ptr != default_base.ptr) self.allocator.free(self.base);
    }

    /// Encrypt content client-side and push to the stream.
    pub fn write(self: *const StreamHandle, content: []const u8) !void {
        const enc = try encryptContent(self.allocator, content, &self.secret);
        defer {
            self.allocator.free(enc.encrypted_hex);
            self.allocator.free(enc.iv_hex);
        }

        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/stream/{s}/write",
            .{ self.base, self.full_token },
        );
        defer self.allocator.free(url);

        const body = try std.json.stringifyAlloc(self.allocator, .{
            .encryptedContent = enc.encrypted_hex,
            .iv = enc.iv_hex,
        }, .{});
        defer self.allocator.free(body);

        try httpPost(self.allocator, url, null, body, null);
    }

    /// Close the stream. Viewers receive a "closed" event and all content self-destructs.
    pub fn close(self: *const StreamHandle) !void {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/stream/{s}/close",
            .{ self.base, self.full_token },
        );
        defer self.allocator.free(url);

        try httpPost(self.allocator, url, null, "{}", null);
    }

    /// Watch the stream. Calls `callback` with each decrypted message.
    /// Blocks until the stream is closed, expired, or a network error occurs.
    /// Automatically reconnects using SSE Last-Event-ID.
    pub fn watch(
        self: *const StreamHandle,
        allocator: Allocator,
        callback: *const fn ([]const u8) void,
    ) !void {
        const url = try std.fmt.allocPrint(
            allocator,
            "{s}/api/stream/{s}/events",
            .{ self.base, self.full_token },
        );
        defer allocator.free(url);

        // Pre-derive the AES key once for the reconnect loop
        var key: [32]u8 = undefined;
        try deriveKey(&self.secret, &key);

        try watchSse(allocator, url, &key, callback);
    }
};

// ── Public API ────────────────────────────────────────────────────────────────

/// Read and decrypt a VoidNote.
/// `url_or_token` may be a full URL or a raw 64-char hex token.
/// Caller owns the returned ReadResult and must call `.deinit(allocator)`.
pub fn read(allocator: Allocator, url_or_token: []const u8) !ReadResult {
    return readFrom(allocator, url_or_token, default_base);
}

/// Like `read` but allows overriding the API base URL.
pub fn readFrom(allocator: Allocator, url_or_token: []const u8, base: []const u8) !ReadResult {
    const token = try extractToken(url_or_token);
    const token_id = token[0..32];
    const secret = token[32..64];

    const url = try std.fmt.allocPrint(allocator, "{s}/api/note/{s}", .{ base, token_id });
    defer allocator.free(url);

    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();

    const status = try httpGet(allocator, url, null, &body);
    if (status == 404) return VoidNoteError.HttpError; // note not found / destroyed
    if (status != 200) return VoidNoteError.HttpError;

    // Parse response — API returns snake_case for encrypted_content,
    // but camelCase for viewCount/maxViews. Support both with a flexible parser.
    const RawResponse = struct {
        // ciphertext field — Go SDK returns "encrypted_content"
        encrypted_content: ?[]const u8 = null,
        iv: []const u8 = "",
        title: ?[]const u8 = null,
        // counts — API sends camelCase
        viewCount: u32 = 0,
        view_count: u32 = 0,
        maxViews: u32 = 0,
        max_views: u32 = 0,
        destroyed: bool = false,
    };

    const parsed = std.json.parseFromSlice(
        RawResponse,
        allocator,
        body.items,
        .{ .ignore_unknown_fields = true },
    ) catch return VoidNoteError.JsonParseError;
    defer parsed.deinit();

    const raw = parsed.value;
    const enc_hex = raw.encrypted_content orelse return VoidNoteError.JsonParseError;
    if (enc_hex.len == 0 or raw.iv.len == 0) return VoidNoteError.JsonParseError;

    const content = try decryptContent(allocator, enc_hex, raw.iv, secret);
    errdefer allocator.free(content);

    const title_copy: ?[]u8 = if (raw.title) |t| blk: {
        const tc = try allocator.dupe(u8, t);
        break :blk tc;
    } else null;

    return ReadResult{
        .content = content,
        .title = title_copy,
        .view_count = if (raw.view_count > 0) raw.view_count else raw.viewCount,
        .max_views = if (raw.max_views > 0) raw.max_views else raw.maxViews,
        .destroyed = raw.destroyed,
    };
}

/// Create and encrypt a VoidNote client-side. Requires an API key.
/// Caller owns the returned CreateResult and must call `.deinit(allocator)`.
pub fn create(allocator: Allocator, content: []const u8, opts: CreateOptions) !CreateResult {
    if (opts.api_key.len == 0) return VoidNoteError.MissingApiKey;

    var full_token: [64]u8 = undefined;
    generateToken(&full_token);
    const token_id = full_token[0..32];
    const secret = full_token[32..64];

    const enc = try encryptContent(allocator, content, secret);
    defer {
        allocator.free(enc.encrypted_hex);
        allocator.free(enc.iv_hex);
    }

    const max_views = if (opts.max_views == 0) @as(u8, 1) else opts.max_views;

    const expires_in = if (opts.expires_in == 0) @as(u16, 24) else opts.expires_in;
    const note_type = if (opts.note_type.len == 0) "secure" else opts.note_type;

    const body = try std.json.stringifyAlloc(allocator, .{
        .tokenId = token_id,
        .encryptedContent = enc.encrypted_hex,
        .iv = enc.iv_hex,
        .maxViews = max_views,
        .title = opts.title,
        .expiresIn = expires_in,
        .noteType = note_type,
    }, .{});
    defer allocator.free(body);

    const url = try std.fmt.allocPrint(allocator, "{s}/api/notes", .{opts.base});
    defer allocator.free(url);

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{opts.api_key});
    defer allocator.free(auth);

    var resp_body = std.ArrayList(u8).init(allocator);
    defer resp_body.deinit();

    const status = try httpPost(allocator, url, auth, body, &resp_body);
    if (status != 200 and status != 201) return VoidNoteError.HttpError;

    const RawResult = struct {
        siteUrl: ?[]const u8 = null,
        expiresAt: ?[]const u8 = null,
        expires_at: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        RawResult,
        allocator,
        resp_body.items,
        .{ .ignore_unknown_fields = true },
    ) catch return VoidNoteError.JsonParseError;
    defer parsed.deinit();

    const raw = parsed.value;
    const site_url = raw.siteUrl orelse opts.base;
    const expires_at_raw = raw.expiresAt orelse raw.expires_at orelse "";

    const note_url = try std.fmt.allocPrint(allocator, "{s}/note/{s}", .{ site_url, &full_token });
    const expires_copy = try allocator.dupe(u8, expires_at_raw);
    errdefer allocator.free(note_url);

    return CreateResult{
        .url = note_url,
        .expires_at = expires_copy,
    };
}

/// Create a new Void Stream. Requires an API key.
/// Caller owns the returned StreamHandle and must call `.deinit()`.
pub fn createStream(allocator: Allocator, opts: StreamOptions) !StreamHandle {
    if (opts.api_key.len == 0) return VoidNoteError.MissingApiKey;

    var full_token: [64]u8 = undefined;
    generateToken(&full_token);
    const token_id = full_token[0..32];

    const ttl = if (opts.ttl == 0) @as(u32, 3600) else opts.ttl;

    const body = try std.json.stringifyAlloc(allocator, .{
        .tokenId = token_id,
        .title = opts.title,
        .ttl = ttl,
    }, .{});
    defer allocator.free(body);

    const url = try std.fmt.allocPrint(allocator, "{s}/api/stream", .{opts.base});
    defer allocator.free(url);

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{opts.api_key});
    defer allocator.free(auth);

    var resp_body = std.ArrayList(u8).init(allocator);
    defer resp_body.deinit();

    const status = try httpPost(allocator, url, auth, body, &resp_body);
    if (status != 200 and status != 201) return VoidNoteError.HttpError;

    const RawResult = struct {
        siteUrl: ?[]const u8 = null,
        expiresAt: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        RawResult,
        allocator,
        resp_body.items,
        .{ .ignore_unknown_fields = true },
    ) catch return VoidNoteError.JsonParseError;
    defer parsed.deinit();

    const raw = parsed.value;
    const site_url = raw.siteUrl orelse opts.base;
    const expires_at_raw = raw.expiresAt orelse "";

    const stream_url = try std.fmt.allocPrint(
        allocator,
        "{s}/stream/{s}",
        .{ site_url, &full_token },
    );
    const expires_copy = try allocator.dupe(u8, expires_at_raw);
    const base_copy = try allocator.dupe(u8, opts.base);
    errdefer {
        allocator.free(stream_url);
        allocator.free(expires_copy);
        allocator.free(base_copy);
    }

    var handle = StreamHandle{
        .url = stream_url,
        .expires_at = expires_copy,
        .full_token = full_token,
        .secret = undefined,
        .base = base_copy,
        .allocator = allocator,
    };
    @memcpy(&handle.secret, full_token[32..64]);

    return handle;
}

// ── Internal: crypto ─────────────────────────────────────────────────────────

/// Generate 32 random bytes and hex-encode to a 64-char token.
fn generateToken(out: *[64]u8) void {
    var raw: [32]u8 = undefined;
    fillRandom(&raw);
    hexEncodeFixed(out, &raw);
}

/// Derive a 32-byte AES key from a 32-char hex secret: key = SHA-256(hex_decode(secret))
fn deriveKey(secret_hex: *const [32]u8, out_key: *[32]u8) !void {
    var secret_bytes: [16]u8 = undefined;
    try hexDecodeFixed(&secret_bytes, secret_hex);
    Sha256.hash(&secret_bytes, out_key, .{});
}

const EncryptedResult = struct {
    encrypted_hex: []u8, // caller frees
    iv_hex: []u8, // caller frees
};

/// AES-256-GCM encrypt. Returns hex-encoded ciphertext+tag and iv.
fn encryptContent(allocator: Allocator, plaintext: []const u8, secret_hex: *const [32]u8) !EncryptedResult {
    var key: [32]u8 = undefined;
    try deriveKey(secret_hex, &key);

    var iv: [Aes256Gcm.nonce_length]u8 = undefined;
    fillRandom(&iv);

    // output layout: ciphertext || tag
    const ct_len = plaintext.len + Aes256Gcm.tag_length;
    const ct_buf = try allocator.alloc(u8, ct_len);
    defer allocator.free(ct_buf);

    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(ct_buf[0..plaintext.len], &tag, plaintext, "", iv, key);
    @memcpy(ct_buf[plaintext.len..], &tag);

    const enc_hex = try hexEncodeAlloc(allocator, ct_buf);
    errdefer allocator.free(enc_hex);
    const iv_hex = try hexEncodeAlloc(allocator, &iv);

    return .{ .encrypted_hex = enc_hex, .iv_hex = iv_hex };
}

/// AES-256-GCM decrypt. Returns allocated plaintext (caller frees).
fn decryptContent(allocator: Allocator, enc_hex: []const u8, iv_hex: []const u8, secret_hex: []const u8) ![]u8 {
    if (secret_hex.len != 32) return VoidNoteError.InvalidToken;

    var key: [32]u8 = undefined;
    try deriveKey(secret_hex[0..32], &key);

    const ct_with_tag = try hexDecodeAlloc(allocator, enc_hex);
    defer allocator.free(ct_with_tag);

    if (ct_with_tag.len < Aes256Gcm.tag_length) return VoidNoteError.DecryptionFailed;
    const ct_len = ct_with_tag.len - Aes256Gcm.tag_length;

    const iv = try hexDecodeAlloc(allocator, iv_hex);
    defer allocator.free(iv);
    if (iv.len != Aes256Gcm.nonce_length) return VoidNoteError.DecryptionFailed;

    var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
    @memcpy(&nonce, iv[0..Aes256Gcm.nonce_length]);

    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    @memcpy(&tag, ct_with_tag[ct_len..]);

    const plaintext = try allocator.alloc(u8, ct_len);
    errdefer allocator.free(plaintext);

    Aes256Gcm.decrypt(plaintext, ct_with_tag[0..ct_len], tag, "", nonce, key) catch
        return VoidNoteError.DecryptionFailed;

    return plaintext;
}

// ── Internal: hex ─────────────────────────────────────────────────────────────

const HEX_CHARS = "0123456789abcdef";

/// Encode bytes to a lowercase hex string. Caller owns the result.
fn hexEncodeAlloc(allocator: Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = HEX_CHARS[b >> 4];
        out[i * 2 + 1] = HEX_CHARS[b & 0xf];
    }
    return out;
}

/// Encode bytes into a fixed-size output buffer (must be exactly 2× input).
fn hexEncodeFixed(out: []u8, bytes: []const u8) void {
    std.debug.assert(out.len == bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = HEX_CHARS[b >> 4];
        out[i * 2 + 1] = HEX_CHARS[b & 0xf];
    }
}

fn hexDecodeFixed(out: []u8, hex: []const u8) !void {
    if (hex.len != out.len * 2) return VoidNoteError.InvalidHex;
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16) catch
            return VoidNoteError.InvalidHex;
    }
}

fn hexDecodeAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return VoidNoteError.InvalidHex;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16) catch
            return VoidNoteError.InvalidHex;
    }
    return out;
}

// ── Internal: token ───────────────────────────────────────────────────────────

/// Extract the 64-char hex token from a URL or return the string as-is.
fn extractToken(url_or_token: []const u8) !*const [64]u8 {
    if (std.mem.startsWith(u8, url_or_token, "http")) {
        // Find last path segment
        var it = std.mem.splitBackwardsScalar(u8, url_or_token, '/');
        if (it.next()) |segment| {
            if (segment.len == 64) return segment[0..64];
        }
        return VoidNoteError.InvalidToken;
    }
    if (url_or_token.len != 64) return VoidNoteError.InvalidToken;
    return url_or_token[0..64];
}

// ── Internal: HTTP ────────────────────────────────────────────────────────────

/// Perform a GET request. Returns the HTTP status code.
/// If `body_out` is non-null, the response body is appended to it.
fn httpGet(
    allocator: Allocator,
    url: []const u8,
    auth: ?[]const u8,
    body_out: ?*std.ArrayList(u8),
) !u16 {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var headers_buf: [2]std.http.Header = undefined;
    var header_count: usize = 0;
    if (auth) |a| {
        headers_buf[header_count] = .{ .name = "Authorization", .value = a };
        header_count += 1;
    }

    var storage = std.ArrayList(u8).init(allocator);
    defer storage.deinit();

    const result = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = url },
        .response_storage = .{ .dynamic = &storage },
        .extra_headers = headers_buf[0..header_count],
    });

    if (body_out) |out| {
        try out.appendSlice(storage.items);
    }

    return @intFromEnum(result.status);
}

/// Perform a POST request with a JSON body. Returns the HTTP status code.
/// If `body_out` is non-null, the response body is appended to it.
/// Returns 0 on transport error.
fn httpPost(
    allocator: Allocator,
    url: []const u8,
    auth: ?[]const u8,
    payload: []const u8,
    body_out: ?*std.ArrayList(u8),
) !u16 {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var headers_buf: [2]std.http.Header = undefined;
    var header_count: usize = 0;
    headers_buf[header_count] = .{ .name = "Content-Type", .value = "application/json" };
    header_count += 1;
    if (auth) |a| {
        headers_buf[header_count] = .{ .name = "Authorization", .value = a };
        header_count += 1;
    }

    var storage = std.ArrayList(u8).init(allocator);
    defer storage.deinit();

    const result = try client.fetch(.{
        .method = .POST,
        .location = .{ .url = url },
        .response_storage = .{ .dynamic = &storage },
        .extra_headers = headers_buf[0..header_count],
        .payload = payload,
    });

    if (body_out) |out| {
        try out.appendSlice(storage.items);
    }

    return @intFromEnum(result.status);
}

// ── Internal: SSE ─────────────────────────────────────────────────────────────

/// Subscribe to an SSE endpoint, decrypt each message, and call `callback`.
/// Reconnects automatically using Last-Event-ID until stream closes/expires.
fn watchSse(
    allocator: Allocator,
    url: []const u8,
    key: *const [32]u8,
    callback: *const fn ([]const u8) void,
) !void {
    var last_id_buf: [32]u8 = undefined;
    var last_id_len: usize = 0;

    while (true) {
        // Build headers — optionally include Last-Event-ID
        var headers_buf: [1]std.http.Header = undefined;
        var header_count: usize = 0;
        if (last_id_len > 0) {
            headers_buf[header_count] = .{
                .name = "Last-Event-ID",
                .value = last_id_buf[0..last_id_len],
            };
            header_count += 1;
        }

        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();

        var server_header_buf: [8192]u8 = undefined;

        const uri = std.Uri.parse(url) catch return VoidNoteError.NetworkError;
        var req = client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buf,
            .extra_headers = headers_buf[0..header_count],
        }) catch return VoidNoteError.NetworkError;
        defer req.deinit();

        req.send() catch return VoidNoteError.NetworkError;
        req.finish() catch return VoidNoteError.NetworkError;
        req.wait() catch return VoidNoteError.NetworkError;

        // Read SSE stream line by line
        var buf_reader = std.io.bufferedReader(req.reader());
        const reader = buf_reader.reader();

        var event_id: []u8 = &.{};
        var event_data_buf = std.ArrayList(u8).init(allocator);
        defer event_data_buf.deinit();

        var line_buf: [8192]u8 = undefined;

        while (true) {
            const line = reader.readUntilDelimiterOrEof(&line_buf, '\n') catch break;
            if (line == null) break;
            const raw_line = line.?;
            // Strip trailing \r
            const ln = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
                raw_line[0 .. raw_line.len - 1]
            else
                raw_line;

            if (std.mem.startsWith(u8, ln, "id: ")) {
                event_id = ln[4..];
            } else if (std.mem.startsWith(u8, ln, "data: ")) {
                event_data_buf.clearRetainingCapacity();
                event_data_buf.appendSlice(ln[6..]) catch break;
            } else if (ln.len == 0 and event_data_buf.items.len > 0) {
                // Blank line = end of event
                if (event_id.len > 0 and event_id.len <= last_id_buf.len) {
                    @memcpy(last_id_buf[0..event_id.len], event_id);
                    last_id_len = event_id.len;
                }

                // Parse event JSON
                const data = event_data_buf.items;
                const SseEvent = struct {
                    type: ?[]const u8 = null,
                    enc: ?[]const u8 = null,
                    iv: ?[]const u8 = null,
                };
                const parsed = std.json.parseFromSlice(
                    SseEvent,
                    allocator,
                    data,
                    .{ .ignore_unknown_fields = true },
                ) catch {
                    event_data_buf.clearRetainingCapacity();
                    event_id = &.{};
                    continue;
                };
                defer parsed.deinit();

                const evt = parsed.value;

                // Control events
                if (evt.type) |t| {
                    if (std.mem.eql(u8, t, "closed") or std.mem.eql(u8, t, "expired")) {
                        return; // stream done
                    }
                }

                // Message event
                if (evt.enc) |enc_hex| {
                    if (evt.iv) |iv_hex| {
                        if (decryptWithKey(allocator, enc_hex, iv_hex, key)) |plaintext| {
                            callback(plaintext);
                            allocator.free(plaintext);
                        } else |_| {
                            // tampered or wrong key — skip silently
                        }
                    }
                }

                event_data_buf.clearRetainingCapacity();
                event_id = &.{};
            }
        }
        // Connection ended — reconnect (loop continues)
    }
}

/// Decrypt using a pre-derived AES key (avoids re-deriving per message).
fn decryptWithKey(allocator: Allocator, enc_hex: []const u8, iv_hex: []const u8, key: *const [32]u8) ![]u8 {
    const ct_with_tag = try hexDecodeAlloc(allocator, enc_hex);
    defer allocator.free(ct_with_tag);

    const iv_bytes = try hexDecodeAlloc(allocator, iv_hex);
    defer allocator.free(iv_bytes);

    if (ct_with_tag.len < Aes256Gcm.tag_length) return VoidNoteError.DecryptionFailed;
    if (iv_bytes.len != Aes256Gcm.nonce_length) return VoidNoteError.DecryptionFailed;

    const ct_len = ct_with_tag.len - Aes256Gcm.tag_length;
    var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
    @memcpy(&nonce, iv_bytes[0..Aes256Gcm.nonce_length]);
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    @memcpy(&tag, ct_with_tag[ct_len..]);

    const plaintext = try allocator.alloc(u8, ct_len);
    errdefer allocator.free(plaintext);

    Aes256Gcm.decrypt(plaintext, ct_with_tag[0..ct_len], tag, "", nonce, key.*) catch
        return VoidNoteError.DecryptionFailed;

    return plaintext;
}

// ── Internal: platform RNG ────────────────────────────────────────────────────

fn fillRandom(buf: []u8) void {
    switch (builtin.cpu.arch) {
        .wasm32, .wasm64 => @compileError("WASM not supported; provide your own entropy"),
        else => {},
    }
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .openbsd, .dragonfly => {
            const arc4random_buf = struct {
                extern "c" fn arc4random_buf(buf: [*]u8, nbytes: usize) void;
            }.arc4random_buf;
            arc4random_buf(buf.ptr, buf.len);
        },
        .linux => {
            const SYS_getrandom: usize = switch (builtin.cpu.arch) {
                .x86_64 => 318,
                .aarch64 => 278,
                .arm => 384,
                .x86 => 355,
                .riscv64 => 278,
                else => @compileError("getrandom syscall number not defined for this arch"),
            };
            var remaining = buf;
            while (remaining.len > 0) {
                const result = std.os.linux.syscall3(
                    @enumFromInt(SYS_getrandom),
                    @intFromPtr(remaining.ptr),
                    remaining.len,
                    0,
                );
                const n: isize = @bitCast(result);
                if (n <= 0) @panic("getrandom failed");
                remaining = remaining[@intCast(n)..];
            }
        },
        .windows => {
            const BCryptGenRandom = struct {
                extern "bcrypt" fn BCryptGenRandom(
                    ?*anyopaque,
                    [*]u8,
                    u32,
                    u32,
                ) callconv(std.builtin.CallingConvention.winapi) i32;
            }.BCryptGenRandom;
            if (BCryptGenRandom(null, buf.ptr, @intCast(buf.len), 0x00000002) != 0)
                @panic("BCryptGenRandom failed");
        },
        else => @compileError("unsupported platform for fillRandom"),
    }
}

// ── Buy / Credits API ─────────────────────────────────────────────────────────

pub const CryptoOrderOptions = struct {
    api_key: []const u8,
    /// Amount of credits to purchase
    credits: u32,
    /// Cryptocurrency symbol, e.g. "BTC", "ETH", "LTC"
    currency: []const u8,
    base: []const u8 = default_base,
};

pub const CryptoOrder = struct {
    order_id: []const u8,
    address: []const u8,
    amount: []const u8,
    currency: []const u8,
    expires_at: []const u8,

    pub fn deinit(self: CryptoOrder, allocator: Allocator) void {
        allocator.free(self.order_id);
        allocator.free(self.address);
        allocator.free(self.amount);
        allocator.free(self.currency);
        allocator.free(self.expires_at);
    }
};

pub const SubmitPaymentOptions = struct {
    api_key: []const u8,
    /// Order ID returned by `createCryptoOrder`
    order_id: []const u8,
    /// On-chain transaction ID / hash
    tx_id: []const u8,
    base: []const u8 = default_base,
};

pub const SubmitPaymentResult = struct {
    success: bool,
    message: []const u8,

    pub fn deinit(self: SubmitPaymentResult, allocator: Allocator) void {
        allocator.free(self.message);
    }
};

/// Create a crypto payment order to purchase credits. Requires an API key.
/// Caller owns the returned CryptoOrder and must call `.deinit(allocator)`.
pub fn createCryptoOrder(allocator: Allocator, opts: CryptoOrderOptions) !CryptoOrder {
    if (opts.api_key.len == 0) return VoidNoteError.MissingApiKey;

    const body = try std.json.stringifyAlloc(allocator, .{
        .credits = opts.credits,
        .currency = opts.currency,
    }, .{});
    defer allocator.free(body);

    const url = try std.fmt.allocPrint(allocator, "{s}/api/buy/crypto/create-order", .{opts.base});
    defer allocator.free(url);

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{opts.api_key});
    defer allocator.free(auth);

    var resp_body = std.ArrayList(u8).init(allocator);
    defer resp_body.deinit();

    const status = try httpPost(allocator, url, auth, body, &resp_body);
    if (status != 200 and status != 201) return VoidNoteError.HttpError;

    const RawResult = struct {
        orderId: ?[]const u8 = null,
        order_id: ?[]const u8 = null,
        address: ?[]const u8 = null,
        amount: ?[]const u8 = null,
        currency: ?[]const u8 = null,
        expiresAt: ?[]const u8 = null,
        expires_at: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        RawResult,
        allocator,
        resp_body.items,
        .{ .ignore_unknown_fields = true },
    ) catch return VoidNoteError.JsonParseError;
    defer parsed.deinit();

    const raw = parsed.value;
    const order_id_raw = raw.orderId orelse raw.order_id orelse return VoidNoteError.JsonParseError;
    const address_raw = raw.address orelse return VoidNoteError.JsonParseError;
    const amount_raw = raw.amount orelse return VoidNoteError.JsonParseError;
    const currency_raw = raw.currency orelse opts.currency;
    const expires_at_raw = raw.expiresAt orelse raw.expires_at orelse "";

    const order_id_copy = try allocator.dupe(u8, order_id_raw);
    errdefer allocator.free(order_id_copy);
    const address_copy = try allocator.dupe(u8, address_raw);
    errdefer allocator.free(address_copy);
    const amount_copy = try allocator.dupe(u8, amount_raw);
    errdefer allocator.free(amount_copy);
    const currency_copy = try allocator.dupe(u8, currency_raw);
    errdefer allocator.free(currency_copy);
    const expires_copy = try allocator.dupe(u8, expires_at_raw);

    return CryptoOrder{
        .order_id = order_id_copy,
        .address = address_copy,
        .amount = amount_copy,
        .currency = currency_copy,
        .expires_at = expires_copy,
    };
}

/// Submit an on-chain transaction ID for a pending crypto order. Requires an API key.
/// Caller owns the returned SubmitPaymentResult and must call `.deinit(allocator)`.
pub fn submitCryptoPayment(allocator: Allocator, opts: SubmitPaymentOptions) !SubmitPaymentResult {
    if (opts.api_key.len == 0) return VoidNoteError.MissingApiKey;

    const body = try std.json.stringifyAlloc(allocator, .{
        .orderId = opts.order_id,
        .txId = opts.tx_id,
    }, .{});
    defer allocator.free(body);

    const url = try std.fmt.allocPrint(allocator, "{s}/api/buy/crypto/submit-tx", .{opts.base});
    defer allocator.free(url);

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{opts.api_key});
    defer allocator.free(auth);

    var resp_body = std.ArrayList(u8).init(allocator);
    defer resp_body.deinit();

    const status = try httpPost(allocator, url, auth, body, &resp_body);
    if (status != 200 and status != 201) return VoidNoteError.HttpError;

    const RawResult = struct {
        success: ?bool = null,
        message: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        RawResult,
        allocator,
        resp_body.items,
        .{ .ignore_unknown_fields = true },
    ) catch return VoidNoteError.JsonParseError;
    defer parsed.deinit();

    const raw = parsed.value;
    const message_copy = try allocator.dupe(u8, raw.message orelse "");

    return SubmitPaymentResult{
        .success = raw.success orelse (status == 200 or status == 201),
        .message = message_copy,
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "encrypt/decrypt round trip" {
    const allocator = std.testing.allocator;

    var token: [64]u8 = undefined;
    generateToken(&token);
    const secret = token[32..64];

    const plaintext = "Hello, VoidNote!";
    const enc = try encryptContent(allocator, plaintext, secret);
    defer {
        allocator.free(enc.encrypted_hex);
        allocator.free(enc.iv_hex);
    }

    const decrypted = try decryptContent(allocator, enc.encrypted_hex, enc.iv_hex, secret);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "token generation is 64 hex chars" {
    var token: [64]u8 = undefined;
    generateToken(&token);

    try std.testing.expectEqual(@as(usize, 64), token.len);
    for (token) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "extractToken from URL" {
    const token_str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const url = "https://voidnote.net/note/" ++ token_str;

    const extracted = try extractToken(url);
    try std.testing.expectEqualStrings(token_str, extracted);
}

test "extractToken from raw token" {
    const token_str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const extracted = try extractToken(token_str);
    try std.testing.expectEqualStrings(token_str, extracted);
}

test "hex encode/decode roundtrip" {
    const allocator = std.testing.allocator;
    const original = [_]u8{ 0x01, 0xab, 0xcd, 0xef, 0x00, 0xff };
    const hex = try hexEncodeAlloc(allocator, &original);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("01abcdef00ff", hex);

    const decoded = try hexDecodeAlloc(allocator, hex);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &original, decoded);
}

test "key derivation is deterministic" {
    const secret: [32]u8 = "aabbccddeeff00112233445566778899".*;
    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    try deriveKey(&secret, &key1);
    try deriveKey(&secret, &key2);
    try std.testing.expectEqual(key1, key2);
}
