**Prompt: Secret Remediation in Git Repository**

**Context:**

You are provided detailed location of hardcoded secrets in a Git repository.
This prompt provides remediation instructions for each occurrence.

**Instructions:**

1. **Leverage provided information** from `list_repo_occurrences` tool: For every occurrence, use the information from
   matches :
    * Leverage the `filepath` to find the file,
    * Use the `matches` to read each element of an occurrence : `indice_start`, `indice_end`, `pre_line_start`,
      `pre_line_end`, `post_line_start` and `post_line_end` for precise secret locations.

2. **Remediation steps for each secret**:

    * Remove hardcoded secrets from the code.
    * Replace them with references to environment variables (e.g., `process.env.API_KEY`, `os.getenv('API_KEY')`).
    * If applicable, run the repository’s package manager to install required dependencies.
      {% if add_to_env %}
    * Add the real secret to a `.env` file,
    * Ensuring `.env` is in `.gitignore`.
      {% endif %}
      {% if env_example %}
    * Add a placeholder to `.env.example` to document expected environment variables.
      {% endif %}

3. **Optional follow-up**:

{% if git_commands %}

* Suggest `git` commands to the user for remediation (staging changes, committing, removing secrets from history).
  {% endif %}



