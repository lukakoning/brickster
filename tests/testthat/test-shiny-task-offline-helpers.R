local_shiny_task_dependencies <- function() {
  skip_if_not_installed("shiny", "1.8.1")
  skip_if_not_installed("mirai", "2.5.1")
  skip_if_not_installed("promises")
}

shiny_task_test_auth <- function(state) {
  list(
    host = "workspace.example.com",
    ready = function() TRUE,
    generation = function() state$generation(),
    access_token = function(async) {
      state$async <- async
      state$token
    }
  )
}

shiny_task_wait <- function(session, until) {
  deadline <- Sys.time() + 10
  while (!shiny::isolate(until()) && Sys.time() < deadline) {
    later::run_now(0.01)
    session$flushReact()
  }
  expect_identical(shiny::isolate(until()), TRUE)
}

test_that("tasks dispatch explicit credentials and arguments to real mirai workers", {
  local_shiny_task_dependencies()
  profile <- "brickster-task-test"
  mirai::daemons(1, .compute = profile)
  withr::defer(mirai::daemons(0, .compute = profile))
  state <- new.env(parent = emptyenv())
  state$generation <- shiny::reactiveVal("login-one")
  state$token <- "alice"
  callback_env <- new.env(parent = baseenv())
  callback_env$app_setting <- "must not accompany the operation"
  operation <- function(host, token, value) {
    list(
      host = host,
      token = token,
      value = value,
      captured = exists("app_setting", inherits = TRUE),
      pid = Sys.getpid()
    )
  }
  environment(operation) <- callback_env
  shiny::testServer(
    function(input, output, session) {
      query <- db_shiny_task(
        shiny_task_test_auth(state),
        operation,
        .compute = profile
      )
    },
    {
      expect_identical(query$invoke(value = 42), TRUE)
      shiny_task_wait(session, function() query$status() == "success")
      result <- query$result()
      expect_identical(result$host, "workspace.example.com")
      expect_identical(result$token, "alice")
      expect_identical(result$value, 42)
      expect_identical(result$captured, FALSE)
      expect_identical(result$pid == Sys.getpid(), FALSE)
      expect_identical(state$async, TRUE)
      expect_identical(exists("app_setting", environment(operation)), TRUE)
    }
  )
})

test_that("tasks stop before dispatch if the login ends during token acquisition", {
  local_shiny_task_dependencies()
  state <- new.env(parent = emptyenv())
  state$generation <- shiny::reactiveVal("login-one")
  state$token <- promises::promise(function(resolve, reject) {
    state$resolve <- resolve
  })
  state$dispatches <- 0L
  local_mocked_bindings(
    mirai = function(...) {
      state$dispatches <- state$dispatches + 1L
      promises::promise_resolve("unexpected")
    },
    .package = "mirai"
  )
  shiny::testServer(
    function(input, output, session) {
      query <- db_shiny_task(
        shiny_task_test_auth(state),
        function(host, token) token
      )
    },
    {
      query$invoke()
      state$generation("login-two")
      state$resolve("alice")
      shiny_task_wait(session, function() query$status() == "initial")
      expect_identical(state$dispatches, 0L)
      error <- tryCatch(query$result(), error = identity)
      expect_s3_class(error, "shiny.silent.error")
    }
  )
})

test_that("current operation failures are exposed and old successful results are hidden", {
  local_shiny_task_dependencies()
  state <- new.env(parent = emptyenv())
  state$generation <- shiny::reactiveVal("login-one")
  state$token <- "alice"
  state$fail <- TRUE
  local_mocked_bindings(
    mirai = function(...) {
      if (state$fail) {
        promises::promise_reject(simpleError("Warehouse permission denied"))
      } else {
        promises::promise_resolve(data.frame(value = 42))
      }
    },
    .package = "mirai"
  )
  shiny::testServer(
    function(input, output, session) {
      query <- db_shiny_task(
        shiny_task_test_auth(state),
        function(host, token) token
      )
    },
    {
      query$invoke()
      shiny_task_wait(session, function() query$status() == "error")
      expect_snapshot(error = TRUE, query$result(), cran = TRUE)
      state$fail <- FALSE
      query$invoke()
      shiny_task_wait(session, function() query$status() == "success")
      expect_equal(query$result(), data.frame(value = 42))
      state$generation("login-two")
      expect_identical(query$status(), "initial")
      error <- tryCatch(query$result(), error = identity)
      expect_s3_class(error, "shiny.silent.error")
    }
  )
})

test_that("tasks reject credential overrides and use from another session", {
  local_shiny_task_dependencies()
  state <- new.env(parent = emptyenv())
  state$generation <- shiny::reactiveVal("login-one")
  state$token <- "alice"
  shiny::testServer(
    function(input, output, session) {
      query <- db_shiny_task(
        shiny_task_test_auth(state),
        function(host, token) token
      )
    },
    {
      expect_snapshot(
        error = TRUE,
        query$invoke(token = "another-user"),
        cran = TRUE
      )
      other <- shiny::MockShinySession$new()
      withr::defer(other$close())
      shiny::withReactiveDomain(
        other,
        shiny::isolate({
          expect_snapshot(error = TRUE, query$invoke(), cran = TRUE)
        })
      )
      session$close()
      expect_snapshot(error = TRUE, query$result(), cran = TRUE)
    }
  )
})
