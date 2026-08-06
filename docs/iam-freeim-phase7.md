# FreeIM IAM integration (Phase 7)

## Goal

Industrial IAM owns platform identity and coarse IM capabilities. FreeIM remains the
real-time transport, while conversation/friend/group membership and chat ACL stay in the
business system that owns them.

```text
IAM
  -> global_user_id
  -> SystemAccess(IM)
  -> im.session.access / im.broadcast.send / im.administration.manage

MES chat business
  -> local Sys_User.User_Id
  -> sessions / members / messages / recall / attachments

FreeIM transport
  -> IAM-derived stable long clientId
  -> Redis routing
  -> WebSocket delivery
```

Do not put conversation ids, friend ids, group ids or mute state into IAM permissions.

## 1. Preparation

Configure FreeIM resource sync before enabling centralized admission:

```text
INDUSTRIAL_SECURITY_PROFILE=IamPrepare
Iam__BootstrapImClientSecret=<strong-secret>
Security__ResourceSync__ClientSecret=<same-secret>
```

IAM registers confidential client:

```text
im-service
```

The browser never receives this secret.

## 2. Permission catalog

FreeIM publishes only platform-level capabilities:

```text
im.session.access
im.broadcast.send
im.administration.manage
```

`im.session.access` means the account may enter the IM transport service. It does not mean
the user belongs to every conversation.

## 3. No synthetic Shadow User

FreeIM has no independent business-user record. `ShadowUserProvisioning=Disabled` keeps the
stable IAM `global_user_id` as the only identity and does not create fake local users.

`RequireSystemAccess=true` still applies. A user must have enabled:

```text
SystemCode = IM
```

before the centralized FreeIM API is reachable.

## 4. Two-level connection ticket

A long-lived IAM access token is never placed in the WebSocket query string.

A centralized client calls:

```text
POST /api/im/connect
Authorization: Bearer <IAM access token>
```

The service verifies `im.session.access`, derives a stable FreeIM transport `clientId` from
`global_user_id`, and asks the existing FreeIM library to issue its native 10-second
handshake token.

The response contains a public path such as:

```text
/im/ws?token=<short-lived-freeim-token>
```

YARP removes `/im` and forwards the socket to FreeIM `/ws` on the backend node.

## 5. Business user id vs transport client id

MES chat tables continue using the existing numeric `Sys_User.User_Id`. Phase 7 does not
rewrite durable message/session/member foreign keys.

`MOL FreeImGateway` converts only the realtime transport identity:

```text
bound MES user
  Sys_User.User_Id = 123
  Sys_User.IamUserId = <global id>

business storage id = 123
transport client id = SHA256(global id) -> positive Int64
```

Unbound Local/IamPrepare users continue using the numeric local id for transport, preserving
rollback compatibility.

## 6. Redis server routing vs browser websocket routing

These are intentionally different concepts.

FreeIM backend node identity:

```text
127.0.0.1:6001
```

Browser public endpoint through YARP:

```text
ws://localhost:5202/im/ws
```

`FreeIM.Servers` in MOL must list actual FreeIM nodes because Redis server channels are
partitioned using those values. `PublicWebSocketBaseUrl` is used only for the browser URL.

At a production HTTPS site override it with the real hostname and `wss://`.

## 7. MES cross-system admission

MES Shadow authorization intentionally keeps Local MES permission as the normal API result.
That generic `IPermissionChecker` must not be used for `im.session.access`, because IM is a
separate system.

`ChatController.Connection/Authorize` therefore performs an explicit central cross-system
check when MES authentication is Centralized:

1. current IAM global user exists;
2. IAM `SystemAccess(IM)` is enabled;
3. IAM permission snapshot contains `im.session.access` or `*`;
4. only then MOL asks FreeIM for the short socket token.

All durable chat operations continue to apply the existing MES session/member ACL.

## 8. Centralized FreeIM profile

After IM resources/roles/system access are prepared:

```text
INDUSTRIAL_SECURITY_PROFILE=Centralized
```

Expected behavior:

```text
Authentication = Centralized
Authorization  = Centralized
SystemCode = IM
ShadowUserProvisioning = Disabled
RequireSystemAccess = true
```

Suggested platform roles may include:

```text
IM_USER       -> im.session.access
IM_OPERATOR   -> im.session.access + im.broadcast.send
IM_ADMIN      -> all three IM capabilities
```

Role names are suggestions only; APIs authorize by permission code.

## 9. Health and Gateway

FreeIM listens at:

```text
http://localhost:6001
```

and exposes public health endpoints including:

```text
/health/live
/health/ready
/health/traffic
```

YARP actively checks `/health/traffic` and provides:

```text
/api/im/** -> FreeIM HTTP APIs
/im/ws/**  -> FreeIM WebSocket
```

## 10. Failure behavior

IAM unavailable:

- existing connected sockets continue until transport disconnect;
- new centralized connection tickets fail closed;
- MES durable message writes/offline delivery logic remain separate;
- FreeIM Redis/backend health remains independently observable.

Redis unavailable:

- FreeIM real-time delivery is unavailable;
- MES chat business should continue persisting durable messages according to its existing
  offline behavior.

## 11. Security hardening note

The native FreeIM handshake token has a 10-second Redis TTL. The current upstream library
reads the token during `/ws` acceptance, but the repository still needs a verified atomic
`GET+DEL` (or Redis `GETDEL`) implementation before this token can be described as strictly
single-use. Phase 7 does not claim that replay hardening is complete until that change is
successfully built and tested.

The long-lived IAM access token is nevertheless not exposed in the WebSocket URL.

## 12. Acceptance checklist

- IAM contains IM resources from `permission-manifest.json`;
- users have `SystemAccess(IM)`;
- regular IM users have `im.session.access`;
- `/api/im/connect` returns a 10-second FreeIM ticket;
- `/im/ws?token=...` upgrades through YARP to backend port 6001;
- MES direct/group chat still uses local business user ids;
- a migrated receiver gets realtime messages through the IAM-derived transport client id;
- a non-IM IAM user receives 403 from MES connection authorization and FreeIM direct API;
- stopping IAM blocks new tickets but does not mutate chat membership/ACL data;
- stopping Redis degrades real-time transport without corrupting durable MES chat data.
