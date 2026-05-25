"""GitHub primitive tools (issues, code, repo metadata, contributors).

These tools call the GitHub REST API. They honor an optional ``GITHUB_TOKEN``
env var; without one, GitHub's anonymous rate limit (60 req/h) applies.
``search_github_code`` requires a token.
"""
