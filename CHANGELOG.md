# Changelog

## [0.7.0](https://github.com/GitGuardian/ggmcp/compare/v0.6.10...v0.7.0) (2026-08-06)


### Features

* **logging:** route uvicorn logs through the structlog pipeline ([#189](https://github.com/GitGuardian/ggmcp/issues/189)) ([e0c2a40](https://github.com/GitGuardian/ggmcp/commit/e0c2a40303d3e9b6f8a4aa3549ad159104904266))
* **logging:** structured logging with structlog + secret scrubbing ([#187](https://github.com/GitGuardian/ggmcp/issues/187)) ([7d8d0b9](https://github.com/GitGuardian/ggmcp/commit/7d8d0b93db8b9c3b0aa067c0c03847151f1b8562))
* **logging:** trace every tool call via on_call_tool middleware ([#188](https://github.com/GitGuardian/ggmcp/issues/188)) ([d285251](https://github.com/GitGuardian/ggmcp/commit/d2852510551985f382bdb532ec969ef65ec720fb))
* **logging:** value-based secret scrubbing for logs ([#190](https://github.com/GitGuardian/ggmcp/issues/190)) ([558c549](https://github.com/GitGuardian/ggmcp/commit/558c549aa948e7eae4f7446b52d4a4ad327fcd6f))
* **mcp_server:** log selected auth mode at startup ([#177](https://github.com/GitGuardian/ggmcp/issues/177)) ([9b62d78](https://github.com/GitGuardian/ggmcp/commit/9b62d786593ca80ef05a1d938fd88644321ada62))


### Bug Fixes

* **ci:** derive cosign image ref from meta tags, not repository_owner ([#186](https://github.com/GitGuardian/ggmcp/issues/186)) ([edb604c](https://github.com/GitGuardian/ggmcp/commit/edb604c340d15da42b4927f6a6a04705efcb0421))
* **oauth_proxy:** read token name/lifetime via settings, not os.environ ([#171](https://github.com/GitGuardian/ggmcp/issues/171)) ([16c1faf](https://github.com/GitGuardian/ggmcp/commit/16c1fafd2dd015ea0df5de499641aedbb94c8bef))
* **oauth:** use CSPRNG for PKCE verifier and CSRF state ([#170](https://github.com/GitGuardian/ggmcp/issues/170)) ([5bc5899](https://github.com/GitGuardian/ggmcp/commit/5bc5899cc9a7ce4b32755e8b438773b87bffe8dd))
* **register_tools:** correct revoke_secret required_scopes to secrets:write ([#169](https://github.com/GitGuardian/ggmcp/issues/169)) ([6d42280](https://github.com/GitGuardian/ggmcp/commit/6d42280da011839679e05d42a0dc218d076cab02))
* **sentry:** init Sentry before the FastMCP server import so MCPIntegration instruments tools ([#195](https://github.com/GitGuardian/ggmcp/issues/195)) ([272fc26](https://github.com/GitGuardian/ggmcp/commit/272fc265467b39c020a92191313d98387f7f6758))
* **tools:** give params wrappers a default so all-optional tools accept {} ([#206](https://github.com/GitGuardian/ggmcp/issues/206)) ([92d47ed](https://github.com/GitGuardian/ggmcp/commit/92d47edad43a96d7df064b91bb15e66abcca5ee0))


### Documentation

* **env.example:** fix default values and documentation ([#180](https://github.com/GitGuardian/ggmcp/issues/180)) ([e22d31a](https://github.com/GitGuardian/ggmcp/commit/e22d31a8f4f9f2bd639a764ad0af35f58eb3f7bf))
* **readme:** fix Docker image name to mcp-server ([#178](https://github.com/GitGuardian/ggmcp/issues/178)) ([616c47f](https://github.com/GitGuardian/ggmcp/commit/616c47f77fe959e281351afc5bf3328fe3269da4))
