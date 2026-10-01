# configuration supplies one workspace with SQL and refresh scopes

    Code
      print(config)
    Output
      <db_shiny_config>
        Workspace: workspace.example.com 
        API scopes: sql 

# providers remain bound to the original login through refresh and logout

    Code
      provider$token()
    Condition
      Error in `check_current()`:
      ! The authorization is no longer available; sign in and obtain current credentials.

# a provider cannot switch to a replacement login

    Code
      old$token()
    Condition
      Error in `check_current()`:
      ! The authorization is no longer available; sign in and obtain current credentials.

# closing a session invalidates retained credentials

    Code
      provider$token()
    Condition
      Error in `check_current()`:
      ! The authorization is no longer available; sign in and obtain current credentials.

# configuration rejects an insufficient worker token lifetime

    Code
      db_shiny_config("workspace.example.com", "registered-app",
        "http://localhost:8080/callback", min_valid_for = 5)
    Condition
      Error in `db_shiny_config()`:
      ! `min_valid_for` must be one finite number of at least 40 seconds.

