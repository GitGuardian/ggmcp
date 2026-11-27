# Changelog

## [0.10.0](https://github.com/GitGuardian/ggmcp/compare/v0.9.0...v0.10.0) (2026-11-27)


### Features

* **client:** identify MCP client, protocol, and tool on outgoing API calls ([#216](https://github.com/GitGuardian/ggmcp/issues/216)) ([63063d3](https://github.com/GitGuardian/ggmcp/commit/63063d334696a79d115a2f6b47f4c0335c80b068))


### Bug Fixes

* classify unknown MCP tool calls as client mistakes ([#256](https://github.com/GitGuardian/ggmcp/issues/256)) ([24a250b](https://github.com/GitGuardian/ggmcp/commit/24a250b58f35ae5ac584f73ecef63ec8a173d568))
* disable FastMCP listen streams to allow worker recycling ([#259](https://github.com/GitGuardian/ggmcp/issues/259)) ([d5e7f4d](https://github.com/GitGuardian/ggmcp/commit/d5e7f4de9196eabe60756e17c049910062f0f1cc))
* **logging:** cut rejected-token and per-request log noise ([#255](https://github.com/GitGuardian/ggmcp/issues/255)) ([da90947](https://github.com/GitGuardian/ggmcp/commit/da90947515966e5004dd937b76022e1ad51e0cc3))

## [0.9.0](https://github.com/GitGuardian/ggmcp/compare/v0.8.0...v0.9.0) (2026-11-26)


### ⚠ BREAKING CHANGES

* **tools:** list tool results carry per_page instead of page_size. The output field has no alias; code that reads page_size from a result must read per_page.

### Features

* create share links for public incidents ([#257](https://github.com/GitGuardian/ggmcp/issues/257)) ([2497cda](https://github.com/GitGuardian/ggmcp/commit/2497cda831fcc43e0f7bb27f358cb69fbb0f3312))
* **tools:** advertise per_page on every list tool, keep page_size as an alias ([#251](https://github.com/GitGuardian/ggmcp/issues/251)) ([98012e2](https://github.com/GitGuardian/ggmcp/commit/98012e262192e4b3eeb6120d27dc871123c8a35b))


### Bug Fixes

* **deps:** bump Python dependencies ([#254](https://github.com/GitGuardian/ggmcp/issues/254)) ([d795582](https://github.com/GitGuardian/ggmcp/commit/d7955826ea51a8357d9b1968d10b6aab00497d1e))


### Documentation

* remove migration notes from README ([#246](https://github.com/GitGuardian/ggmcp/issues/246)) ([cb44d24](https://github.com/GitGuardian/ggmcp/commit/cb44d24a36c222bb66672f2185638d5c6156bb6c))

## [0.8.0](https://github.com/GitGuardian/ggmcp/compare/v0.7.5...v0.8.0) (2026-11-19)


### ⚠ BREAKING CHANGES

* **tools:** gg_mcp_server.sse_app:app no longer exists. Serve gg_mcp_server.http_app:app instead.

### Features

* **tools:** move to FastMCP 4 and give every tool one contract ([#241](https://github.com/GitGuardian/ggmcp/issues/241)) ([f895868](https://github.com/GitGuardian/ggmcp/commit/f89586877853a47b41dbfd2297d342fee1697350))

## [0.7.5](https://github.com/GitGuardian/ggmcp/compare/v0.7.4...v0.7.5) (2026-11-10)


### Bug Fixes

* **deps:** bump authlib, dnspython and joserfc ([#242](https://github.com/GitGuardian/ggmcp/issues/242)) ([980313e](https://github.com/GitGuardian/ggmcp/commit/980313eb9a2d5ef34c864385f9e944e0cad105f6))

## [0.7.4](https://github.com/GitGuardian/ggmcp/compare/v0.7.3...v0.7.4) (2026-10-22)


### Bug Fixes

* **deps:** bump certifi to 2026.10.19 ([082d148](https://github.com/GitGuardian/ggmcp/commit/082d148fe52416545efe6ebbc97a16e3cbf3cfb4))

## [0.7.3](https://github.com/GitGuardian/ggmcp/compare/v0.7.2...v0.7.3) (2026-10-14)


### Bug Fixes

* **honeytokens:** return honeytoken values unmasked ([#237](https://github.com/GitGuardian/ggmcp/issues/237)) ([701f72e](https://github.com/GitGuardian/ggmcp/commit/701f72ee2e8694aad94b3d74d59c3d0a4d90125d))

## [0.7.2](https://github.com/GitGuardian/ggmcp/compare/v0.7.1...v0.7.2) (2026-10-12)


### Bug Fixes

* **deps:** bump pyjwt to 2.14.0 ([#235](https://github.com/GitGuardian/ggmcp/issues/235)) ([10888c2](https://github.com/GitGuardian/ggmcp/commit/10888c2f54b85367d54f6cf76739793529f93ef6))
* **deps:** bump urllib3 to 2.8.0 ([#234](https://github.com/GitGuardian/ggmcp/issues/234)) ([7ae3740](https://github.com/GitGuardian/ggmcp/commit/7ae3740ee55da3e492180d712fe085458d44b7a0))

## [0.7.1](https://github.com/GitGuardian/ggmcp/compare/v0.7.0...v0.7.1) (2026-10-07)


### Bug Fixes

* **custom_tags:** drop the redundant pre-create POST /custom_tags loop ([#219](https://github.com/GitGuardian/ggmcp/issues/219)) ([73b6c8b](https://github.com/GitGuardian/ggmcp/commit/73b6c8b6d59e4e28b798eee7996f4b1cc8fe6ba1))
* **deps:** bump anyio to 4.14.2 ([#233](https://github.com/GitGuardian/ggmcp/issues/233)) ([c149bb2](https://github.com/GitGuardian/ggmcp/commit/c149bb2dfbb3a02d61d88fe1328cc0fbe3b3c4d0))

## [0.7.0](https://github.com/GitGuardian/ggmcp/compare/v0.6.10...v0.7.0) (2026-08-18)


### Features

* **logging:** consolidate MCP logging on the structlog foundation ([#198](https://github.com/GitGuardian/ggmcp/issues/198)) ([6c8007f](https://github.com/GitGuardian/ggmcp/commit/6c8007f129d51f2e0f4ce634c5d8a46b5769e18a))
* **logging:** route uvicorn logs through the structlog pipeline ([#189](https://github.com/GitGuardian/ggmcp/issues/189)) ([e0c2a40](https://github.com/GitGuardian/ggmcp/commit/e0c2a40303d3e9b6f8a4aa3549ad159104904266))
* **logging:** structured logging with structlog + secret scrubbing ([#187](https://github.com/GitGuardian/ggmcp/issues/187)) ([7d8d0b9](https://github.com/GitGuardian/ggmcp/commit/7d8d0b93db8b9c3b0aa067c0c03847151f1b8562))
* **logging:** trace every tool call via on_call_tool middleware ([#188](https://github.com/GitGuardian/ggmcp/issues/188)) ([d285251](https://github.com/GitGuardian/ggmcp/commit/d2852510551985f382bdb532ec969ef65ec720fb))
* **logging:** value-based secret scrubbing for logs ([#190](https://github.com/GitGuardian/ggmcp/issues/190)) ([558c549](https://github.com/GitGuardian/ggmcp/commit/558c549aa948e7eae4f7446b52d4a4ad327fcd6f))
* **mcp_server:** log selected auth mode at startup ([#177](https://github.com/GitGuardian/ggmcp/issues/177)) ([9b62d78](https://github.com/GitGuardian/ggmcp/commit/9b62d786593ca80ef05a1d938fd88644321ada62))


### Bug Fixes

* **ci:** derive cosign image ref from meta tags, not repository_owner ([#186](https://github.com/GitGuardian/ggmcp/issues/186)) ([edb604c](https://github.com/GitGuardian/ggmcp/commit/edb604c340d15da42b4927f6a6a04705efcb0421))
* **deps:** bump cryptography to 50.0.0 (CVE-2026-69247) ([#217](https://github.com/GitGuardian/ggmcp/issues/217)) ([18e4791](https://github.com/GitGuardian/ggmcp/commit/18e479145b292f6d03a94b9ae06de58b168cdbe6))
* **oauth_proxy:** read token name/lifetime via settings, not os.environ ([#171](https://github.com/GitGuardian/ggmcp/issues/171)) ([16c1faf](https://github.com/GitGuardian/ggmcp/commit/16c1fafd2dd015ea0df5de499641aedbb94c8bef))
* **oauth:** use CSPRNG for PKCE verifier and CSRF state ([#170](https://github.com/GitGuardian/ggmcp/issues/170)) ([5bc5899](https://github.com/GitGuardian/ggmcp/commit/5bc5899cc9a7ce4b32755e8b438773b87bffe8dd))
* **register_tools:** correct revoke_secret required_scopes to secrets:write ([#169](https://github.com/GitGuardian/ggmcp/issues/169)) ([6d42280](https://github.com/GitGuardian/ggmcp/commit/6d42280da011839679e05d42a0dc218d076cab02))
* **sentry:** init Sentry before the FastMCP server import so MCPIntegration instruments tools ([#195](https://github.com/GitGuardian/ggmcp/issues/195)) ([272fc26](https://github.com/GitGuardian/ggmcp/commit/272fc265467b39c020a92191313d98387f7f6758))
* **sentry:** scrub MCP tool arguments and free-form fields before send ([#215](https://github.com/GitGuardian/ggmcp/issues/215)) ([508f15b](https://github.com/GitGuardian/ggmcp/commit/508f15bc4a3da31aa35fb4cea1e6affbbc377eb5))
* **tools:** give params wrappers a default so all-optional tools accept {} ([#206](https://github.com/GitGuardian/ggmcp/issues/206)) ([92d47ed](https://github.com/GitGuardian/ggmcp/commit/92d47edad43a96d7df064b91bb15e66abcca5ee0))


### Documentation

* **env.example:** fix default values and documentation ([#180](https://github.com/GitGuardian/ggmcp/issues/180)) ([e22d31a](https://github.com/GitGuardian/ggmcp/commit/e22d31a8f4f9f2bd639a764ad0af35f58eb3f7bf))
* **readme:** fix Docker image name to mcp-server ([#178](https://github.com/GitGuardian/ggmcp/issues/178)) ([616c47f](https://github.com/GitGuardian/ggmcp/commit/616c47f77fe959e281351afc5bf3328fe3269da4))
