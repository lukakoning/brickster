#' Create a Databricks OAuth provider
#'
#' @description
#' Discover a workspace's OpenID Connect configuration for use with shinyOAuth.
#' This provider is supplied by brickster and works with Databricks on Azure,
#' AWS, and GCP. No Databricks resources are created.
#'
#' @param host Databricks workspace hostname or HTTPS workspace URL.
#' @param token_auth_style Client authentication method: `"header"` for a
#'   confidential application with a client secret, or `"public"` for an
#'   application registered without a secret.
#' @returns A shinyOAuth `OAuthProvider`. Discovery makes an HTTPS request to
#'   the workspace's `/oidc/.well-known/openid-configuration` endpoint.
#' @family Databricks Authentication Helpers
#' @export
db_oauth_provider <- function(
  host = db_host(),
  token_auth_style = c("header", "public")
) {
  rlang::check_installed("shinyOAuth", version = "0.6.1")
  host <- db_auth_workspace_host(host)
  shinyOAuth::oauth_provider_oidc_discover(
    issuer = paste0("https://", host, "/oidc/.well-known/openid-configuration"),
    name = "databricks",
    token_auth_style = match.arg(token_auth_style),
    use_pkce = TRUE,
    use_nonce = TRUE,
    id_token_validation = TRUE,
    userinfo_required = FALSE
  )
}

#' Use a Shiny user's authorization with Databricks
#'
#' @description
#' Configure Databricks sign-in, wrap your app's UI, and obtain credentials for
#' the signed-in user's SQL and REST requests. Databricks applies that user's
#' existing permissions to each request.
#'
#' @param host Databricks workspace hostname or HTTPS workspace URL.
#' @param client_id Client ID of a custom Databricks OAuth application.
#' @param redirect_uri The exact callback URL registered for the application.
#' @param client_secret The registered client secret, or `NULL` for a public
#'   OAuth application. Read secrets from your deployment configuration.
#' @param scopes Databricks API scopes, default `"sql"`. Use `"all-apis"` for
#'   REST APIs beyond SQL. Identity and refresh scopes are added automatically.
#' @param min_valid_for Minimum remaining access-token lifetime in seconds,
#'   default 300. Allow enough time for one background query to finish.
#' @param id OAuth module ID. Use the same ID for UI and server.
#' @param config A configuration returned by `db_shiny_config()`.
#' @param ui Your Shiny UI. This can be a UI object or a function.
#' @param auto_redirect Whether to start sign-in automatically.
#' @param async Whether to offload OAuth network operations. Default `TRUE`;
#'   configure mirai daemons or a future plan before starting your app. This
#'   setting does not offload SQL, DBI, or REST calls; use [db_shiny_task()] for
#'   background data operations.
#' @param reauth_after_seconds Time until a new login is required, default
#'   eight hours. Refresh alone does not extend this authorization lifetime.
#'
#' @details
#' These helpers require shinyOAuth's development access-token API (version
#' 0.6.1.9000 or later); CRAN 0.6.1 supports the provider but not these session
#' helpers. Install the development release from `lukakoning/shinyOAuth` until
#' these APIs are released on CRAN.
#'
#' Call `db_shiny_config()` once outside `server()`. Call `db_shiny_server()`
#' inside `server()` to create a separate authorization for each Shiny session.
#' The returned `token_provider()` captures the current login and can be passed
#' to brickster REST functions or [DBI::dbConnect()]. It refreshes before sending
#' requests and becomes unusable after logout, a replacement login, or session
#' closure. It must remain in the owning Shiny process and reactive context.
#'
#' For background queries, use [db_shiny_task()]. It obtains a fixed token
#' asynchronously, runs the operation with mirai, and checks the current login
#' before displaying results or errors. For a custom `shiny::ExtendedTask`, call
#' `access_token(async = TRUE)` in the Shiny process and pass the resolved fixed
#' token to the worker. The token retains its workspace binding and expiry;
#' workers cannot refresh it. Compare the captured `generation()` with the
#' current value before displaying either results or errors. Logout invalidates
#' providers and pending token acquisition; it does not cancel a statement
#' already submitted.
#' See `vignette("shiny", package = "brickster")` for a complete app.
#'
#' @returns
#' `db_shiny_config()` returns a `db_shiny_config` with an OAuth client and
#' workspace settings. `db_shiny_ui()` returns a Shiny UI function that routes
#' OAuth callbacks. `db_shiny_server()` returns a list of session helpers:
#' * `ready()`: whether the current grant covers the configured API scopes.
#' * `identity()`: selected validated ID-token claims in `id_token_claims`.
#' * `generation()`: current login ID, or `NULL` when signed out.
#' * `token_provider()`: refreshable credentials bound to this login.
#' * `access_token(async = FALSE)`: a fixed token, or a promise when `async = TRUE`.
#' * `login()` and `logout()`: start sign-in and clear the current login.
#' * `host`: the configured workspace hostname.
#'
#' @family Databricks Authentication Helpers
#' @name db_shiny
NULL

#' @rdname db_shiny
#' @export
db_shiny_config <- function(
  host,
  client_id,
  redirect_uri,
  client_secret = NULL,
  scopes = "sql",
  min_valid_for = 300
) {
  db_shiny_require()
  host <- db_auth_workspace_host(host)
  purrr::iwalk(
    list(
      client_id = client_id,
      redirect_uri = redirect_uri,
      client_secret = client_secret
    ),
    function(value, name) {
      if (name == "client_secret" && is.null(value)) {
        return(invisible(NULL))
      }
      if (
        !is.character(value) ||
          length(value) != 1L ||
          is.na(value) ||
          !nzchar(trimws(value))
      ) {
        cli::cli_abort("{.arg {name}} must be one non-empty string.")
      }
    }
  )
  if (
    !is.numeric(min_valid_for) ||
      length(min_valid_for) != 1L ||
      !is.finite(min_valid_for) ||
      min_valid_for < 40
  ) {
    cli::cli_abort(
      "{.arg min_valid_for} must be one finite number of at least 40 seconds."
    )
  }
  if (
    !is.character(scopes) ||
      !length(scopes) ||
      anyNA(scopes) ||
      any(!nzchar(scopes)) ||
      any(grepl("\\s", scopes))
  ) {
    cli::cli_abort(
      "{.arg scopes} must contain Databricks API scope names, for example {.val sql}."
    )
  }
  identity_scopes <- c("openid", "profile", "email", "offline_access")
  api_scopes <- setdiff(scopes, identity_scopes)
  if (!length(api_scopes)) {
    cli::cli_abort(
      "Include at least one Databricks API scope in {.arg scopes}."
    )
  }
  public <- is.null(client_secret)
  provider <- db_oauth_provider(
    host,
    token_auth_style = if (public) "public" else "header"
  )
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = client_id,
    client_secret = if (public) character() else client_secret,
    redirect_uri = redirect_uri,
    scopes = union(identity_scopes, scopes),
    resource_bases = c(workspace = paste0("https://", host, "/api/")),
    required_scopes = api_scopes,
    label = "Databricks"
  )
  structure(
    list(
      client = client,
      host = host,
      scopes = api_scopes,
      min_valid_for = min_valid_for
    ),
    class = "db_shiny_config"
  )
}

#' @export
print.db_shiny_config <- function(x, ...) {
  cat(
    "<db_shiny_config>\n  Workspace:",
    x$host,
    "\n  API scopes:",
    paste(x$scopes, collapse = ", "),
    "\n"
  )
  invisible(x)
}

#' @rdname db_shiny
#' @export
db_shiny_ui <- function(id, config, ui) {
  db_shiny_check_config(config)
  shinyOAuth::oauth_ui(ui, id = id, client = config$client)
}

#' @rdname db_shiny
#' @export
db_shiny_server <- function(
  id,
  config,
  auto_redirect = TRUE,
  async = TRUE,
  reauth_after_seconds = 8 * 60 * 60
) {
  db_shiny_check_config(config)
  if (is.null(shiny::getDefaultReactiveDomain())) {
    cli::cli_abort("Call {.fn db_shiny_server} inside a Shiny server session.")
  }
  if (
    !is.numeric(reauth_after_seconds) ||
      length(reauth_after_seconds) != 1L ||
      !is.finite(reauth_after_seconds) ||
      reauth_after_seconds <= 0
  ) {
    cli::cli_abort(
      "{.arg reauth_after_seconds} must be one finite positive number of seconds."
    )
  }
  auth <- shinyOAuth::oauth_module_server(
    id,
    config$client,
    auto_redirect = auto_redirect,
    async = async,
    indefinite_session = FALSE,
    reauth_after_seconds = reauth_after_seconds,
    refresh_proactively = TRUE,
    revoke_on_session_end = FALSE
  )
  db_shiny_session(auth, config)
}

db_shiny_require <- function() {
  rlang::check_installed(
    "shinyOAuth",
    version = "0.6.1.9000",
    reason = "to use its connection() and access_token() APIs; install the development release from lukakoning/shinyOAuth"
  )
}

db_shiny_check_config <- function(config) {
  db_shiny_require()
  if (!inherits(config, "db_shiny_config")) {
    cli::cli_abort("{.arg config} must be returned by {.fn db_shiny_config}.")
  }
}

db_shiny_session <- function(auth, config) {
  session <- shiny::getDefaultReactiveDomain()
  current <- shiny::reactive(auth$connection())
  check_current <- function(connection) {
    if (
      isTRUE(session$isClosed()) ||
        !identical(shiny::isolate(current())$id, connection$id)
    ) {
      cli::cli_abort(
        "The authorization is no longer available; sign in and obtain current credentials."
      )
    }
    invisible(NULL)
  }
  acquire <- function(connection, async = FALSE, force_refresh = FALSE) {
    check_current(connection)
    finish <- function(token) {
      check_current(connection)
      db_check_bearer_token(token)
      attr(token, "brickster_host") <- config$host
      attr(token, "brickster_expires_at") <- connection$summary()$expires_at
      token
    }
    token <- connection$access_token(
      required_scopes = config$scopes,
      min_valid_for = config$min_valid_for,
      force_refresh = force_refresh,
      async = async
    )
    if (async) {
      promises::then(promises::promise_resolve(token), finish)
    } else {
      finish(token)
    }
  }
  list(
    host = config$host,
    ready = function() {
      connection <- current()
      !is.null(connection) && connection$has_scopes(config$scopes)
    },
    identity = function() {
      shiny::req(current())$identity(
        claims = c("iss", "sub", "name", "email", "preferred_username")
      )
    },
    generation = function() current()$id,
    token_provider = function() {
      connection <- shiny::req(current())
      db_token_provider(config$host, function(force_refresh = FALSE) {
        acquire(connection, force_refresh = force_refresh)
      })
    },
    access_token = function(async = FALSE) {
      if (!is.logical(async) || length(async) != 1L || is.na(async)) {
        cli::cli_abort("{.arg async} must be TRUE or FALSE.")
      }
      if (async) {
        rlang::check_installed("promises")
      }
      perform <- function() {
        connection <- current()
        if (is.null(connection)) {
          cli::cli_abort("Sign in before acquiring a query token.")
        }
        acquire(connection, async = async)
      }
      if (async) {
        tryCatch(perform(), error = function(error) {
          promises::promise_reject(error)
        })
      } else {
        perform()
      }
    },
    login = function() auth$request_login(),
    logout = function() auth$logout()
  )
}

#' Run Databricks operations in the background of a Shiny app
#'
#' @description
#' Create a Shiny `ExtendedTask` that obtains the signed-in user's credentials
#' asynchronously and runs your function with mirai. Results and errors from an
#' earlier login are hidden. Repeated invocations while busy are ignored.
#'
#' @param auth Session helpers returned by [db_shiny_server()].
#' @param fun A function accepting `host` and `token`, such as [db_sql_query()].
#'   For a custom function, pass its other inputs through `invoke()` and use
#'   qualified package calls such as `brickster::db_sql_query()`. Custom functions
#'   run with a base environment, without variables from the app's environment.
#' @param button Optional ID of a `bslib::input_task_button()` in this module.
#' @param .compute Optional mirai compute profile. Configure its daemons before
#'   starting the app; `NULL` uses the default profile.
#'
#' @details
#' Call once inside `server()` or a module. Configure `mirai::daemons()` outside
#' `server()`. `fun` receives only the workspace host, a fixed access token, and
#' the arguments passed to `invoke()`. A worker cannot refresh the token.
#' Already submitted Databricks statements continue after logout.
#'
#' `invoke()` must be called in the owning session's reactive context. It checks
#' sign-in, snapshots the arguments and login, and starts asynchronous token
#' acquisition. It does not queue a second operation while one is running.
#' `result()` follows `shiny::ExtendedTask$result()` behavior for operations
#' that have not started or are running. It checks the current login before
#' returning data or raising an operation error.
#'
#' @returns A list with three methods:
#' * `invoke(...)`: returns `TRUE` invisibly when started, or `FALSE` when busy.
#'   Supply arguments for `fun`, excluding `host` and `token`.
#' * `result()`: returns the operation's value in a reactive output. It hides
#'   outcomes from earlier logins and raises errors from the current operation.
#' * `status()`: reactive status, `"initial"`, `"running"`, `"success"`, or
#'   `"error"`. Completed outcomes from an earlier login report `"initial"`.
#' @family Databricks Authentication Helpers
#' @export
db_shiny_task <- function(auth, fun, button = NULL, .compute = NULL) {
  rlang::check_installed("shiny", version = "1.8.1")
  rlang::check_installed("mirai", version = "2.5.1")
  rlang::check_installed("promises")
  session <- shiny::getDefaultReactiveDomain()
  if (is.null(session)) {
    cli::cli_abort("Call {.fn db_shiny_task} inside a Shiny server session.")
  }
  if (
    !is.list(auth) ||
      !all(purrr::map_lgl(
        auth[c("ready", "generation", "access_token")],
        is.function
      ))
  ) {
    cli::cli_abort("{.arg auth} must be returned by {.fn db_shiny_server}.")
  }
  host <- db_auth_workspace_host(auth$host)
  if (!is.function(fun) || is.primitive(fun)) {
    cli::cli_abort(
      "{.arg fun} must be a function accepting {.arg host} and {.arg token}."
    )
  }
  if (
    !all(c("host", "token") %in% names(formals(fun))) &&
      !"..." %in% names(formals(fun))
  ) {
    cli::cli_abort("{.arg fun} must accept {.arg host} and {.arg token}.")
  }
  if (!isNamespace(environment(fun))) {
    environment(fun) <- baseenv()
  }
  if (!is.null(button)) {
    rlang::check_installed("bslib", version = "0.7.0")
    if (!rlang::is_string(button) || !nzchar(button)) {
      cli::cli_abort("{.arg button} must be one task-button ID or NULL.")
    }
  }
  if (
    !is.null(.compute) && (!rlang::is_string(.compute) || !nzchar(.compute))
  ) {
    cli::cli_abort("{.arg .compute} must be one mirai compute profile or NULL.")
  }
  check_session <- function() {
    caller <- shiny::getDefaultReactiveDomain()
    if (
      isTRUE(session$isClosed()) ||
        is.null(caller) ||
        !identical(session$rootScope(), caller$rootScope())
    ) {
      cli::cli_abort("Use this task in its owning Shiny session.")
    }
  }
  current <- function(generation) {
    !isTRUE(session$isClosed()) &&
      identical(shiny::isolate(auth$generation()), generation)
  }
  task <- shiny::ExtendedTask$new(function(token_promise, generation, args) {
    pending <- promises::then(token_promise, function(token) {
      check_session()
      if (!current(generation)) {
        cli::cli_abort("The authorization ended before the operation started.")
      }
      db_check_bearer_token(token)
      db_check_token_host(token, host)
      operation <- quote(
        do.call(.fun, c(list(host = .host, token = .token), .inputs))
      )
      work <- rlang::inject(
        mirai::mirai(
          !!operation,
          .fun = fun,
          .host = host,
          .token = token,
          .inputs = args,
          .compute = .compute
        )
      )
      promises::as.promise(work)
    })
    promises::then(
      pending,
      function(value) {
        list(generation = generation, value = value, error = NULL)
      },
      function(error) list(generation = generation, value = NULL, error = error)
    )
  })
  if (!is.null(button)) {
    bslib::bind_task_button(task, button)
  }
  list(
    invoke = function(...) {
      check_session()
      if (identical(shiny::isolate(task$status()), "running")) {
        return(invisible(FALSE))
      }
      shiny::req(auth$ready())
      args <- list(...)
      if (any(c("host", "token") %in% names(args))) {
        cli::cli_abort(
          "The task supplies {.arg host} and {.arg token}; pass only operation arguments."
        )
      }
      generation <- auth$generation()
      token <- tryCatch(
        auth$access_token(async = TRUE),
        error = promises::promise_reject
      )
      task$invoke(promises::promise_resolve(token), generation, args)
      invisible(TRUE)
    },
    result = function() {
      check_session()
      shiny::req(auth$ready())
      generation <- auth$generation()
      outcome <- task$result()
      shiny::req(identical(outcome$generation, generation))
      if (!is.null(outcome$error)) {
        stop(outcome$error)
      }
      outcome$value
    },
    status = function() {
      check_session()
      generation <- auth$generation()
      status <- task$status()
      if (identical(status, "success")) {
        outcome <- task$result()
        if (!identical(outcome$generation, generation)) {
          return("initial")
        }
        if (!is.null(outcome$error)) {
          return("error")
        }
      }
      status
    }
  )
}
