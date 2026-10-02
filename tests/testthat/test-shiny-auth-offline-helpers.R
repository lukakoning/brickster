local_databricks_discovery <- function(.local_envir = parent.frame()) {
  testthat::skip_if_not_installed("shinyOAuth", "0.6.1")
  metadata <- list(
    issuer = "https://workspace.example.com/oidc",
    authorization_endpoint = "https://workspace.example.com/oidc/v1/authorize",
    token_endpoint = "https://workspace.example.com/oidc/v1/token",
    jwks_uri = "https://workspace.example.com/oidc/v1/keys",
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256"),
    token_endpoint_auth_methods_supported = list("client_secret_basic", "none"),
    code_challenge_methods_supported = list("S256"),
    scopes_supported = as.list(c(
      "openid",
      "profile",
      "email",
      "offline_access",
      "sql",
      "all-apis"
    ))
  )
  withr::local_options(
    httr2_mock = function(req) {
      if (
        !identical(
          req$url,
          "https://workspace.example.com/oidc/.well-known/openid-configuration"
        )
      ) {
        stop("Unexpected network request")
      }
      httr2::response(
        status_code = 200L,
        headers = list(`Content-Type` = "application/json"),
        body = charToRaw(jsonlite::toJSON(metadata, auto_unbox = TRUE))
      )
    },
    .local_envir = .local_envir
  )
}

shiny_test_token <- function(
  access = "alice",
  scopes = c("openid", "sql"),
  expires = 3600
) {
  shinyOAuth::OAuthToken(
    access_token = access,
    refresh_token = "synthetic-refresh",
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + expires,
    granted_scopes = scopes,
    granted_scopes_verified = TRUE
  )
}

shiny_test_config <- function() {
  testthat::skip_if_not_installed("shinyOAuth", "0.6.1.9000")
  db_shiny_config(
    "workspace.example.com",
    "registered-app",
    "http://localhost:8080/callback",
    client_secret = "synthetic-secret"
  )
}

test_that("Databricks discovery enables validated OIDC and PKCE", {
  local_databricks_discovery()
  provider <- db_oauth_provider("https://WORKSPACE.example.com/")
  expect_identical(provider@issuer, "https://workspace.example.com/oidc")
  expect_identical(
    provider@auth_url,
    "https://workspace.example.com/oidc/v1/authorize"
  )
  expect_identical(
    provider@token_url,
    "https://workspace.example.com/oidc/v1/token"
  )
  expect_identical(provider@use_pkce, TRUE)
  expect_identical(provider@pkce_method, "S256")
  expect_identical(provider@use_nonce, TRUE)
  expect_identical(provider@id_token_validation, TRUE)
  expect_identical(provider@userinfo_required, FALSE)
  expect_identical(provider@token_auth_style, "header")
  expect_identical(
    db_oauth_provider("workspace.example.com", "public")@token_auth_style,
    "public"
  )
})

test_that("configuration supplies one workspace with SQL and refresh scopes", {
  local_databricks_discovery()
  config <- shiny_test_config()
  expect_identical(config$host, "workspace.example.com")
  expect_identical(config$scopes, "sql")
  expect_setequal(
    config$client@scopes,
    c("openid", "profile", "email", "offline_access", "sql")
  )
  expect_identical(
    config$client@resource_bases,
    c(workspace = "https://workspace.example.com/api")
  )
  expect_identical(config$client@token_targets, list())
  expect_snapshot(print(config), cran = TRUE)
  public <- db_shiny_config(
    "workspace.example.com",
    "registered-app",
    "http://localhost:8080/callback",
    scopes = "all-apis"
  )
  expect_identical(public$client@provider@token_auth_style, "public")
  expect_identical(public$scopes, "all-apis")
  expect_type(
    db_shiny_ui("auth", config, shiny::fluidPage("Example")),
    "closure"
  )
})

test_that("invalid app settings are rejected before workspace discovery", {
  skip_if_not_installed("shinyOAuth", "0.6.1.9000")
  local_mocked_bindings(
    db_oauth_provider = function(...) stop("Workspace discovery must not run")
  )
  args <- list(
    host = "workspace.example.com",
    client_id = "registered-app",
    redirect_uri = "http://localhost:8080/callback",
    client_secret = "synthetic-secret"
  )
  purrr::walk(c("client_id", "redirect_uri", "client_secret"), function(name) {
    values <- list("", " ", NA_character_, 123, c("first", "second"))
    if (name != "client_secret") {
      values <- c(values, list(NULL))
    }
    purrr::walk(values, function(value) {
      invalid <- args
      invalid[name] <- list(value)
      expect_error(
        do.call(db_shiny_config, invalid),
        paste0(name, ".*must be one non-empty string")
      )
    })
  })
})

test_that("providers remain bound to the original login through refresh and logout", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE
      )
      auth <- db_shiny_session(oauth, config)
    },
    {
      expect_identical(auth$ready(), FALSE)
      expect_null(auth$generation())
      oauth$token <- shiny_test_token()
      session$flushReact()
      expect_identical(auth$ready(), TRUE)
      generation <- auth$generation()
      provider <- auth$token_provider()
      expect_identical(as.character(provider$token()), "alice")
      expect_identical(attr(auth$access_token(), "brickster_host"), config$host)
      oauth$token <- shiny_test_token("alice-refreshed")
      session$flushReact()
      expect_identical(auth$generation(), generation)
      expect_identical(as.character(provider$token()), "alice-refreshed")
      auth$logout()
      session$flushReact()
      expect_identical(auth$ready(), FALSE)
      expect_null(auth$generation())
      expect_snapshot(error = TRUE, provider$token(), cran = TRUE)
    }
  )
})

test_that("a provider cannot switch to a replacement login", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE
      )
      auth <- db_shiny_session(oauth, config)
    },
    {
      oauth$token <- shiny_test_token()
      session$flushReact()
      old <- auth$token_provider()
      generation <- auth$generation()
      auth$logout()
      oauth$token <- shiny_test_token("bob")
      session$flushReact()
      expect_identical(identical(generation, auth$generation()), FALSE)
      expect_identical(as.character(auth$token_provider()$token()), "bob")
      expect_snapshot(error = TRUE, old$token(), cran = TRUE)
    }
  )
})

test_that("missing API grants make the session unready", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE
      )
      auth <- db_shiny_session(oauth, config)
    },
    {
      oauth$token <- shiny_test_token(scopes = "openid")
      session$flushReact()
      expect_identical(auth$ready(), FALSE)
      error <- tryCatch(auth$access_token(), error = identity)
      expect_s3_class(error, "shinyOAuth_access_error")
      expect_identical(error$context$reason, "insufficient_scope")
    }
  )
})

test_that("closing a session invalidates retained credentials", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE
      )
      auth <- db_shiny_session(oauth, config)
    },
    {
      oauth$token <- shiny_test_token()
      session$flushReact()
      provider <- auth$token_provider()
      session$close()
      expect_snapshot(error = TRUE, provider$token(), cran = TRUE)
    }
  )
})

test_that("late asynchronous token acquisition cannot outlive a login", {
  skip_if_not_installed("shiny")
  skip_if_not_installed("promises")
  state <- new.env(parent = emptyenv())
  state$resolved <- FALSE
  state$error <- NULL
  state$resolve <- NULL
  pending <- promises::promise(function(resolve, reject) {
    state$resolve <- resolve
  })
  shiny::testServer(
    function(input, output, session) {
      selected <- shiny::reactiveVal(list(
        id = "first-login",
        access_token = function(...) pending,
        summary = function() list(expires_at = as.numeric(Sys.time()) + 3600)
      ))
      auth <- db_shiny_session(
        list(connection = selected),
        list(
          host = "workspace.example.com",
          scopes = "sql",
          min_valid_for = 300
        )
      )
    },
    {
      promises::then(
        auth$access_token(async = TRUE),
        onFulfilled = function(token) state$resolved <- TRUE,
        onRejected = function(error) state$error <- error
      )
      selected(NULL)
      session$flushReact()
      state$resolve("late-token")
      purrr::walk(seq_len(10), ~ later::run_now(0.01))
      expect_identical(state$resolved, FALSE)
      expect_s3_class(state$error, "error")
      expect_match(conditionMessage(state$error), "no longer available")
    }
  )
})

test_that("expired credentials refresh through the owning OAuth module", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  state <- new.env(parent = emptyenv())
  state$calls <- 0L
  local_mocked_bindings(
    refresh_token = function(client, token, ...) {
      state$calls <- state$calls + 1L
      shiny_test_token("refreshed")
    },
    .package = "shinyOAuth"
  )
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE,
        indefinite_session = TRUE
      )
      auth <- db_shiny_session(oauth, config)
    },
    {
      oauth$token <- shiny_test_token(expires = -10)
      session$flushReact()
      provider <- auth$token_provider()
      generation <- auth$generation()
      expect_identical(as.character(provider$token()), "refreshed")
      expect_identical(auth$generation(), generation)
      expect_identical(state$calls, 1L)
    }
  )
})

test_that("asynchronous acquisition delivers a fixed token with its expiry", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  state <- new.env(parent = emptyenv())
  state$token <- NULL
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE
      )
      auth <- db_shiny_session(oauth, config)
    },
    {
      oauth$token <- shiny_test_token()
      session$flushReact()
      pending <- auth$access_token(async = TRUE)
      expect_s3_class(pending, "promise")
      promises::then(pending, function(token) state$token <- token)
      purrr::walk(seq_len(10), ~ later::run_now(0.01))
      expect_identical(as.character(state$token), "alice")
      expect_identical(attr(state$token, "brickster_host"), config$host)
      expect_gt(
        attr(state$token, "brickster_expires_at"),
        as.numeric(Sys.time()) + 300
      )
    }
  )
})

test_that("one session cannot use another session's OAuth provider", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  state <- new.env(parent = emptyenv())
  server <- function(input, output, session) {
    oauth <- shinyOAuth::oauth_module_server(
      "auth",
      config$client,
      auto_redirect = FALSE
    )
    auth <- db_shiny_session(oauth, config)
  }
  shiny::testServer(server, {
    oauth$token <- shiny_test_token("alice")
    session$flushReact()
    state$alice <- auth$token_provider()
    other <- shiny::MockShinySession$new()
    withr::defer(other$close())
    shiny::withReactiveDomain(
      other,
      shiny::isolate({
        oauth2 <- shinyOAuth::oauth_module_server(
          "auth",
          config$client,
          auto_redirect = FALSE
        )
        auth2 <- db_shiny_session(oauth2, config)
        oauth2$token <- shiny_test_token("bob")
        other$flushReact()
        expect_identical(as.character(auth2$token_provider()$token()), "bob")
        error <- tryCatch(state$alice$token(), error = identity)
        expect_s3_class(error, "shinyOAuth_access_error")
        expect_identical(error$context$reason, "authorization_unavailable")
      })
    )
    other$close()
    expect_identical(as.character(state$alice$token()), "alice")
  })
})

test_that("the server helper creates an initially signed-out session", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  shiny::testServer(
    function(input, output, session) {
      auth <- db_shiny_server(
        "auth",
        config,
        auto_redirect = FALSE,
        async = FALSE
      )
    },
    {
      expect_identical(auth$host, config$host)
      expect_identical(auth$ready(), FALSE)
      expect_null(auth$generation())
      expect_type(auth$login, "closure")
      expect_type(auth$logout, "closure")
    }
  )
})

test_that("configuration rejects an insufficient worker token lifetime", {
  local_databricks_discovery()
  skip_if_not_installed("shinyOAuth", "0.6.1.9000")
  expect_snapshot(
    error = TRUE,
    db_shiny_config(
      "workspace.example.com",
      "registered-app",
      "http://localhost:8080/callback",
      min_valid_for = 5
    ),
    cran = TRUE
  )
})

test_that("child modules share one login and discard their results on logout", {
  local_databricks_discovery()
  skip_if_not_installed("shiny", "1.8.1")
  skip_if_not_installed("mirai", "2.5.1")
  skip_if_not_installed("promises")
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  state <- new.env(parent = emptyenv())
  state$tokens <- character()
  local_mocked_bindings(
    mirai = function(.expr, .fun, .host, .token, .inputs, .compute) {
      state$tokens <- c(state$tokens, as.character(.token))
      promises::promise_resolve(.inputs$value)
    },
    .package = "mirai"
  )
  data_module <- function(id, auth) {
    shiny::moduleServer(id, function(input, output, session) {
      list(
        query = db_shiny_task(auth, function(host, token, value) value),
        provider = function() auth$token_provider()
      )
    })
  }
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE
      )
      auth <- db_shiny_session(oauth, config)
      first <- data_module("first", auth)
      second <- data_module("second", auth)
    },
    {
      oauth$token <- shiny_test_token()
      session$flushReact()
      first$query$invoke(value = "first module")
      second$query$invoke(value = "second module")
      deadline <- Sys.time() + 10
      while (
        any(c(first$query$status(), second$query$status()) == "running") &&
          Sys.time() < deadline
      ) {
        later::run_now(0.01)
        session$flushReact()
      }
      expect_identical(first$query$result(), "first module")
      expect_identical(second$query$result(), "second module")
      expect_identical(state$tokens, c("alice", "alice"))
      provider <- first$provider()
      oauth$token <- shiny_test_token("alice-refreshed")
      session$flushReact()
      expect_identical(as.character(provider$token()), "alice-refreshed")
      expect_identical(first$query$result(), "first module")
      auth$logout()
      session$flushReact()
      purrr::walk(list(first$query, second$query), function(query) {
        expect_identical(query$status(), "initial")
        expect_s3_class(
          tryCatch(query$result(), error = identity),
          "shiny.silent.error"
        )
      })
      expect_error(provider$token(), "authorization is no longer available")
    }
  )
})

test_that("an existing shinyOAuth connection supplies login-bound credentials", {
  local_databricks_discovery()
  config <- shiny_test_config()
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  shiny::testServer(
    function(input, output, session) {
      oauth <- shinyOAuth::oauth_module_server(
        "auth",
        config$client,
        auto_redirect = FALSE
      )
    },
    {
      oauth$token <- shiny_test_token()
      session$flushReact()
      connection <- shiny::req(oauth$connection())
      provider <- db_token_provider(
        config$host,
        function(force_refresh = FALSE) {
          connection$access_token(
            required_scopes = "sql",
            min_valid_for = 300,
            force_refresh = force_refresh
          )
        }
      )
      expect_identical(provider$token(), "alice")
      oauth$token <- shiny_test_token("alice-refreshed")
      session$flushReact()
      expect_identical(provider$token(), "alice-refreshed")
      oauth$logout()
      oauth$token <- shiny_test_token("bob")
      session$flushReact()
      error <- tryCatch(provider$token(), error = identity)
      expect_s3_class(error, "shinyOAuth_access_error")
      expect_identical(error$context$reason, "authorization_unavailable")
    }
  )
})
