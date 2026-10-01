sign_provider_request <- function(req) {
  policy <- req$policies$auth_sign
  do.call(policy$fun, c(list(req = req, cache = policy$cache), policy$params))
}

test_that("deferred and parallel requests obtain current independent credentials", {
  state <- new.env(parent = emptyenv())
  state$alice <- "alice-first"
  state$bob <- "bob-first"
  alice <- db_token_provider(
    "https://WORKSPACE.example.com/",
    function(force_refresh = FALSE) state$alice
  )
  bob <- db_token_provider(
    "workspace.example.com",
    function(force_refresh = FALSE) state$bob
  )
  requests <- purrr::map(list(alice, bob), function(token) {
    db_sql_warehouse_list(
      host = "workspace.example.com",
      token = token,
      perform_request = FALSE
    )
  })
  state$alice <- "alice-refreshed"
  signed <- purrr::map(requests, sign_provider_request)
  expect_identical(
    purrr::map_chr(signed, ~ rlang::wref_value(.x$headers$Authorization)),
    c("Bearer alice-refreshed", "Bearer bob-first")
  )
  expect_null(requests[[1]]$headers$Authorization)
  expect_identical(requests[[1]]$options$followlocation, FALSE)
  expect_snapshot(print(alice), cran = TRUE)
})

test_that("workspace mismatch is rejected before the callback runs", {
  provider <- db_token_provider(
    "workspace.example.com",
    function(force_refresh = FALSE) stop("Callback ran")
  )
  expect_snapshot(
    error = TRUE,
    db_sql_warehouse_list(
      host = "other.example.com",
      token = provider,
      perform_request = FALSE
    ),
    cran = TRUE
  )
})

test_that("callback failure never falls back to another credential source", {
  withr::local_envvar(DATABRICKS_TOKEN = "global-credential")
  local_mocked_bindings(db_auth_type = function() stop("Fallback ran"))
  provider <- db_token_provider(
    "workspace.example.com",
    function(force_refresh = FALSE) stop("Authorization ended")
  )
  req <- db_sql_warehouse_list(
    host = "workspace.example.com",
    token = provider,
    perform_request = FALSE
  )
  expect_snapshot(error = TRUE, sign_provider_request(req), cran = TRUE)
})

test_that("empty callback results do not create anonymous requests", {
  provider <- db_token_provider(
    "workspace.example.com",
    function(force_refresh = FALSE) NULL
  )
  req <- db_sql_warehouse_list(
    host = "workspace.example.com",
    token = provider,
    perform_request = FALSE
  )
  expect_snapshot(error = TRUE, sign_provider_request(req), cran = TRUE)
})

test_that("HTTP 401 requests one forced refresh", {
  state <- new.env(parent = emptyenv())
  state$refresh <- logical()
  state$headers <- character()
  provider <- db_token_provider(
    "workspace.example.com",
    function(force_refresh = FALSE) {
      state$refresh <- c(state$refresh, force_refresh)
      if (force_refresh) "refreshed" else "first"
    }
  )
  local_mocked_bindings(
    req_perform1 = function(req, req_prep, ...) {
      req_prep <- sign_provider_request(req_prep)
      state$headers <- c(
        state$headers,
        rlang::wref_value(req_prep$headers$Authorization)
      )
      httr2::response(
        status_code = if (length(state$headers) == 1L) 401L else 200L,
        headers = list(
          `Content-Type` = "application/json",
          `WWW-Authenticate` = 'Bearer error="invalid_token"'
        ),
        body = charToRaw('{"warehouses":[]}')
      )
    },
    .package = "httr2"
  )
  expect_length(
    db_sql_warehouse_list(host = "workspace.example.com", token = provider),
    0L
  )
  expect_identical(state$refresh, c(FALSE, TRUE))
  expect_identical(state$headers, c("Bearer first", "Bearer refreshed"))
})

test_that("fixed worker tokens retain workspace and expiry checks", {
  token <- "worker-token"
  attr(token, "brickster_host") <- "workspace.example.com"
  attr(token, "brickster_expires_at") <- as.numeric(Sys.time()) + 600
  req <- db_sql_warehouse_list(
    host = "workspace.example.com",
    token = token,
    perform_request = FALSE
  )
  expect_identical(
    rlang::wref_value(req$headers$Authorization),
    "Bearer worker-token"
  )
  expect_snapshot(
    error = TRUE,
    db_sql_warehouse_list(
      host = "other.example.com",
      token = token,
      perform_request = FALSE
    ),
    cran = TRUE
  )
})

test_that("expiring worker tokens stop before sending a request", {
  token <- "worker-token"
  attr(token, "brickster_expires_at") <- as.numeric(Sys.time()) + 10
  expect_snapshot(
    error = TRUE,
    db_sql_warehouse_list(
      host = "workspace.example.com",
      token = token,
      perform_request = FALSE
    ),
    cran = TRUE
  )
})

test_that("providers reject insecure workspace URLs", {
  expect_snapshot(
    error = TRUE,
    db_token_provider(
      "http://workspace.example.com",
      function(force_refresh = FALSE) "token"
    ),
    cran = TRUE
  )
})

test_that("DBI retains a provider across queries and rejects ended authorization", {
  state <- new.env(parent = emptyenv())
  state$token <- "first"
  state$headers <- character()
  provider <- db_token_provider(
    "workspace.example.com",
    function(force_refresh = FALSE) {
      if (is.null(state$token)) {
        stop("Authorization ended")
      }
      state$token
    }
  )
  local_mocked_bindings(dbi_connection_opened = function(conn) invisible(TRUE))
  local_mocked_bindings(
    req_perform1 = function(req, req_prep, ...) {
      req_prep <- sign_provider_request(req_prep)
      state$headers <- c(
        state$headers,
        rlang::wref_value(req_prep$headers$Authorization)
      )
      httr2::response(
        status_code = 200L,
        headers = list(`Content-Type` = "application/json"),
        body = charToRaw(
          '{"statement_id":"test","status":{"state":"SUCCEEDED"},"manifest":{"format":"JSON_ARRAY","total_chunk_count":1,"total_row_count":1,"schema":{"columns":[{"name":"value","type_name":"INT"}]}},"result":{"data_array":[["1"]]}}'
        )
      )
    },
    .package = "httr2"
  )
  con <- DBI::dbConnect(
    DatabricksSQL(),
    warehouse_id = "wh",
    host = "workspace.example.com",
    token = provider,
    disposition = "INLINE",
    show_progress = FALSE
  )
  expect_identical(con@token, provider)
  state$token <- "refreshed"
  expect_identical(names(DBI::dbGetQuery(con, "SELECT 1")), "value")
  expect_identical(state$headers, c("Bearer first", "Bearer refreshed"))
  state$token <- NULL
  expect_snapshot(error = TRUE, DBI::dbGetQuery(con, "SELECT 1"), cran = TRUE)
})
