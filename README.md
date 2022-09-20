# hsbc-assess-4

This is a demo implementation of a simple user authentication (register and login)
and authorization (permission check) service.

The requirement documentation only requires a group of functions as the interface.
To make the service actually useful, we still need a gateway layer (such as HTTP
or gRPC).

You can play with the service (technically, a library) by running `go test -v ./...`
in the project folder, or clicking 'run package tests' or something similar in your
IDE.

As of 9/20/2022, the code coverage of `lib/auth` test cases is more than 95%.

## Design

The API revolves around user IDs and role IDs. Even if duplicate user/role names
are not allowed, it is good to have a never-changing unique ID for each entity. That
ensures that our server is able to support features like the separation of user
login and display name.

To better support ID operation, additional APIs converting between IDs and names
are provided.

Caveat: As a primitive demo, this implementation is NOT goroutine-safe.

### Data Structure

We use maps with user ID, user name, role ID, and role name as keys. That, as a
equivalent of MySQL Hash Index, ensures O(1) run time of each basic operation.

### Token Expiry

Generally, auth tokens expire in a lazy manner. That means they are only removed
from memory when accessed by `Authenticate()`. But it is quite possible that a
token is never used again, even discarded, by the client after a short time. In
that case, lazy expiry is not enough to keep memory usage under control.

To solve that issue, this project introduced the "Server Epoch", which splits the
server uptime into 1-hour windows. Tokens, in addition to being stored in maps,
are queued once per window. If we are in the 4th window, those tokens queued in the
1st window are at least 2 hours away, and it is safe to remove them once for all.
This mass removal is triggered each time the current Epoch changes (i.e. on the next
token-verifying request after the server uptime crosses a full-hour mark). On a busy
server, that is equivalent to "once per hour", but without background timer.

This feature is covered in `TestPruneTokens()`.

## API Reference

See function comments in [auth.go](lib/auth/auth.go). They comply to Godoc rules.

## External Dependencies

This repo depends on [Testify](https://github.com/stretchr/testify) for convenience
of unit testing.

The Go toolchain should be able to sort that out automatically. If you encounter
any trouble, try setting GOPROXY (such as `goproxy.cn` for mainland China).
