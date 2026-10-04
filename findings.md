# Security Audit — tai7sy/card-system (发卡系统) v3.15

Goal: **unauthenticated, 0-click vulnerability that leaks AK/SK** (cloud storage credentials).

## Framework dictionary
- Laravel 5.5, PHP >=7.0. JWT auth (tymon/jwt-auth 1.0.0-rc.5).
- Routes: `routes/api.php` is mounted under **`/api`** prefix (RouteServiceProvider::mapApiRoutes), middleware group `api` = **only `bindings`** (NO auth, NO throttle). `routes/web.php` not prefixed, group `web` = BladeMinify only.
- Admin routes protected by `auth.token` (App\Http\Middleware\AuthenticateToken, JWT).
- Code is obfuscated (var names like `$sp62e4cd`) but logic intact.

### Where the AK/SK (and other secrets) live — the SINKS to reach
Stored in `system` key-value table via `App\System::_get/_set`; loaded into live Laravel `config()` by `app/Providers/ConfigServiceProvider.php`:
- `storage_s3_access_key` / `storage_s3_secret_key`  → `config('filesystems.disks.s3.key/secret')`
- `storage_oss_access_key` / `storage_oss_secret_key` → `config('filesystems.disks.oss.access_id/access_key')`
- `storage_qiniu_access_key` / `storage_qiniu_secret_key` → `config('filesystems.disks.qiniu.*')`
- `mail_smtp_password`, `sms_api_key`, `sendcloud_key`, `vcode_geetest_key`
- Pay gateway secrets in `App\Pay->config` (JSON, DB).
- `.env`: APP_KEY, DB creds. `bootstrap/cache/config.php` (if `config:cache` run) contains ALL resolved secrets incl. AK/SK.
- Admin read path (authed): `GET /api/admin/system/storage` returns all storage_* values.

### Unauthenticated entry points
- `/api/admin/captcha`, `/api/admin/auth/login`, `/api/admin/auth/token`
- **`/api/admin/web/logs/{token}` → Admin\Dashboard@logsView  (OUTSIDE auth group — UNAUTH)**
- `/api/shop/*` (product, product/password, coupon, buy, record/get), `/api/qrcode/query/{pay_id}`
- web.php: `/`, `/storage/{file_path}` (renderImage), `/pay/*`, `/qrcode/pay/*`, `/c/{id}`, `/p/{id}`, `/s`
- if `app.debug`: `/install`, `/test` (DevController)

---

## CONFIRMED FINDINGS

### F1 [HIGH] Unauthenticated access to Log Viewer via broken token check (auth bypass)
- Location: `app/Http/Controllers/Admin/Dashboard.php` → `logsView()`; route `routes/api.php` `Route::any('admin/web/logs/{token}', ...)` (outside auth.token group).
- Code: `function logsView($req,$token){ if ($user = Cache::get($token)) { Cache::put($token,$user,15); return (new LaravelLogViewerController())->index(); } else throw Unauthorized; }`
- Flaw: the only gate is `Cache::get($token)` being TRUTHY, where `$token` is the attacker-controlled URL segment. `settings.all` is an always-present cache key (App\System::_init does `Cache::remember('settings.all',10,...)`, refreshed on every request by ConfigServiceProvider) holding a non-empty array → truthy.
- PoC: `GET /api/admin/web/logs/settings.all`  → renders rap2hpoutre/laravel-log-viewer index (unauthenticated).
- Reachability: UNAUTH, 0-click. Cache driver default `file` (.env.example CACHE_DRIVER=file).
- Log viewer version v0.13.0: `l`/`dl` params use `\Crypt::decrypt` (need APP_KEY) so arbitrary-path read needs APP_KEY; BUT index page (resources/views/vendor/laravel-log-viewer/log.blade.php) server-generates valid encrypted switch-links for EVERY `storage/logs/*.log`, renders full log table (level/context/date/text/stack), AND exposes `?dl=`(download) and `?del=`/`?delall=true`(delete).
- EXTRA: `?delall=true` needs NO crypto token → unauth attacker can WIPE all logs (anti-forensics / log destruction).
- Other always-present truthy cache keys usable as the bypass token: `settings.all`, `model.pays`.
- Verified: shop_theme/admin blade views echo only curated config (app.logo/name/project) + pays(id/name/img); NO secret echo. `js_tj`/`js_kf` are raw admin JS (stored XSS, admin-set, not AKSK).
- Verified: `systems` table = (name UNIQUE, value longText) KV; secrets stored here. `Pay->config` holds gateway merchant secrets (not exposed to shop).

### F2 [HIGH, enabler for F1→AKSK] Exception handler logs full request headers + raw body
- Location: `app/Exceptions/Handler.php::render()` final branch:
  `Log::error('Uncaught Exception', ['exception'=>$e,'method'=>..,'url'=>$req->fullUrl(),'data'=>file_get_contents('php://input'),'headers'=>$req->header()])`
- Written at `error` level (survives default APP_LOG_LEVEL=error). Captures `Authorization: Bearer <JWT>`, `Cookie`, and raw POST bodies (e.g. admin login email+password) for ANY uncaught exception.
- Chain to AK/SK: F1 (read logs) → harvest admin JWT (replayable; AuthenticateToken even refreshes expired tokens and accepts `?token=`) or admin login credentials → authenticate as admin → `GET /api/admin/system/storage` → OSS/S3/Qiniu AccessKey+SecretKey.
- Dependency (honest): requires an admin/merchant request to have thrown an uncaught (non-Model/Validation/Http) exception at some point — common on real deployments but not attacker-forced.

### F3 [MEDIUM] Hardcoded external MySQL credentials in source
- Location: `app/Product.php::createApiCards()`: `mysqli_connect('localhost','udiddz','tRihPm3sh6yKedtX','udiddz','3306')`.
- Hardcoded creds for external "udid" DB. Not cloud AK/SK; reachable only on paid fulfillment of API products (id 6/11/37). SQL built from str_random (not user input) → not injectable.

---

## Ruled out (negative results)
- Shop endpoints (Product@get, Order@get, Coupon@info, Pay@buy): Eloquent `where()` parameterized; `(int)` casts; `whereRaw` strings static → NO SQLi.
- `Merchant\File@renderImage` (`/storage/{file_path}`): requires `images/` prefix, blocks `..`,`./`,`.\` → NOT arbitrary file read.
- `PayWay::gets` restricts visible fields to id/name/img/fee → pay secrets NOT leaked to shop.
- `Product::setForShop` setVisible whitelist → merchant User secrets NOT serialized to shop.
- Gateway payment drivers = empty git submodule (app/Library/Gateway) — not present in this checkout.
- CurlRequest/UrlShorten use mostly hardcoded hosts; no obvious unauth attacker-controlled-host SSRF to metadata.

## PRIMARY ANSWER — unauth 0-click chain to AK/SK
F1 (unauth log viewer) + F2 (headers/body logged on uncaught exceptions):
1. `GET /api/admin/web/logs/settings.all` → unauth log viewer.
2. Read `card_*.log` → find `Log::error('Uncaught Exception', {headers:{authorization:"Bearer <JWT>"}, data:"<raw body>"})` records from admin/merchant requests.
3. Replay the admin JWT (AuthenticateToken accepts `?token=` and auto-refreshes expired tokens) OR use admin login creds captured in `data`.
4. `GET /api/admin/system/storage` → returns storage_oss_access_key/secret_key, storage_s3_*, storage_qiniu_* = AK/SK.
Attacker actions are pure unauth HTTP (0-click). Only probabilistic link: an admin/merchant request must have thrown an uncaught (non-Model/Validation/Http) exception → logged with headers. High likelihood on a live deployment; not attacker-forced. Direct log read ALSO leaks: customer PII, IPs, DB-error details (DB user/host), and OSS AccessKeyId (on storage errors).

## Verified (closed TODO)
- Blade views echo only curated config + pays(id/name/img); no secret echo. js_tj/js_kf = raw admin JS (stored XSS, admin-set).
- `systems` KV schema confirmed; `Pay->config` gateway secrets not exposed unauth.
- Admin\Pay / app/Pay.php authed. Update.php self-update = CLI/scheduled, not unauth HTTP (out of scope).

## Covered dimensions
auth/authz, SQLi, file read / path traversal, SSTI / config echo, info disclosure (logs/cache), hardcoded secrets, SSRF, deserialization, payment callback logic.
## Not covered / why
- app/Library/Gateway/* payment drivers = empty submodule (not in checkout) → gateway-side SSRF/signature-bypass/secret-logging unverified.
- vendor/ not installed → framework/library internals (OSS/Qiniu SDK error text, exact Crypt behavior) reasoned from pinned versions, not executed.
- Runtime values (whether config:cache ran, actual log contents, which storage driver) deployment-specific.
