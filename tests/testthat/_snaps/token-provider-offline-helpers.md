# deferred requests obtain current independent credentials

    Code
      print(alice)
    Output
      <db_token_provider>
        Workspace: workspace.example.com 

# workspace mismatch is rejected before the callback runs

    Code
      db_sql_warehouse_list(host = "other.example.com", token = provider,
        perform_request = FALSE)
    Condition
      Error in `db_check_token_host()`:
      ! These credentials belong to a different workspace; use their configured `host`.

# callback failure never falls back to another credential source

    Code
      sign_provider_request(req)
    Condition
      Error in `provider$token()`:
      ! Authorization ended

# empty callback results do not create anonymous requests

    Code
      sign_provider_request(req)
    Condition
      Error in `db_check_bearer_token()`:
      ! The token callback must return one non-empty bearer token string.

# fixed worker tokens retain workspace and expiry checks

    Code
      db_sql_warehouse_list(host = "other.example.com", token = token,
        perform_request = FALSE)
    Condition
      Error in `db_check_token_host()`:
      ! These credentials belong to a different workspace; use their configured `host`.

# expiring worker tokens stop before sending a request

    Code
      db_sql_warehouse_list(host = "workspace.example.com", token = token,
        perform_request = FALSE)
    Condition
      Error in `db_check_token_host()`:
      ! The query token is expiring; acquire a fresh token in the owning Shiny session.

# providers reject insecure workspace URLs

    Code
      db_token_provider("http://workspace.example.com", function(force_refresh = FALSE)
        "token")
    Condition
      Error in `db_auth_workspace_host()`:
      ! `host` must contain only a workspace hostname or HTTPS origin.

# DBI retains a provider across queries and rejects ended authorization

    Code
      DBI::dbGetQuery(con, "SELECT 1")
    Condition
      Error in `provider$token()`:
      ! Authorization ended

