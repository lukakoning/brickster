shiny_example_server <- function() {
  app <- new.env(parent = environment(db_shiny_server))
  purrr::walk(
    c("reactiveVal", "observeEvent", "renderText", "renderTable", "req"),
    function(name) app[[name]] <- getExportedValue("shiny", name)
  )
  app$config <- list(host = "workspace.example.com")
  app$warehouse <- "warehouse"
  app$sql <- "SELECT current_user()"
  app$volume_file <- ""
  app$read_data <- function(...) NULL
  path <- system.file("examples/shiny-app/app.R", package = "brickster")
  purrr::walk(parse(path), function(expr) {
    if (
      is.call(expr) &&
        identical(expr[[1]], as.name("<-")) &&
        identical(expr[[2]], as.name("server"))
    ) {
      eval(expr, app)
    }
  })
  app$server
}

shiny_app_tick <- function(session, until) {
  deadline <- Sys.time() + 5
  while (!shiny::isolate(until()) && Sys.time() < deadline) {
    later::run_now(0.01)
    session$flushReact()
  }
  expect_identical(shiny::isolate(until()), TRUE)
}

test_that("the example does not queue repeated load clicks", {
  skip_if_not_installed("shiny", "1.8.1")
  skip_if_not_installed("bslib", "0.7.0")
  skip_if_not_installed("mirai", "2.5.1")
  state <- new.env(parent = emptyenv())
  state$dispatches <- 0L
  state$tokens <- 0L
  local_mocked_bindings(
    db_shiny_server = function(...) {
      list(
        host = "workspace.example.com",
        ready = function() TRUE,
        generation = function() "login-one",
        identity = function() list(id_token_claims = list(sub = "alice")),
        access_token = function(...) {
          state$tokens <- state$tokens + 1L
          promises::promise_resolve("alice")
        }
      )
    }
  )
  local_mocked_bindings(
    mirai = function(...) {
      state$dispatches <- state$dispatches + 1L
      promises::promise(function(resolve, reject) state$resolve <- resolve)
    },
    .package = "mirai"
  )
  shiny::testServer(shiny_example_server(), {
    session$setInputs(source = "sql", load = 0)
    session$setInputs(load = 1)
    shiny_app_tick(session, function() state$dispatches == 1L)
    session$setInputs(load = 2)
    expect_identical(state$tokens, 1L)
    state$resolve(data.frame(user = "alice"))
    shiny_app_tick(session, function() query$status() == "success")
    expect_identical(state$dispatches, 1L)
    expect_identical(query$result()$user, "alice")
  })
})

test_that("the example suppresses failed operations from a previous login", {
  skip_if_not_installed("shiny", "1.8.1")
  skip_if_not_installed("bslib", "0.7.0")
  skip_if_not_installed("mirai", "2.5.1")
  state <- new.env(parent = emptyenv())
  state$reject <- NULL
  login <- shiny::reactiveVal("login-one")
  local_mocked_bindings(
    db_shiny_server = function(...) {
      list(
        host = "workspace.example.com",
        ready = function() TRUE,
        generation = function() login(),
        identity = function() list(id_token_claims = list(sub = "alice")),
        access_token = function(...) promises::promise_resolve("alice")
      )
    }
  )
  local_mocked_bindings(
    mirai = function(...) {
      promises::promise(function(resolve, reject) state$reject <- reject)
    },
    .package = "mirai"
  )
  shiny::testServer(shiny_example_server(), {
    session$setInputs(source = "sql", load = 0)
    session$setInputs(load = 1)
    shiny_app_tick(session, function() !is.null(state$reject))
    login("login-two")
    state$reject(simpleError("Details from the old user's query"))
    shiny_app_tick(session, function() query$status() == "initial")
    error <- tryCatch(output$data, error = identity)
    expect_s3_class(error, "shiny.silent.error")
    expect_identical(conditionMessage(error), "")
  })
})
