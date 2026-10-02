library(shiny)
library(brickster)

mirai::daemons(2)
onStop(function() mirai::daemons(0))

secret <- Sys.getenv("DATABRICKS_CLIENT_SECRET")
config <- db_shiny_config(
  host = Sys.getenv("DATABRICKS_HOST"),
  client_id = Sys.getenv("DATABRICKS_CLIENT_ID"),
  redirect_uri = Sys.getenv("SHINY_OAUTH_REDIRECT_URI"),
  client_secret = if (nzchar(secret)) secret else NULL,
  scopes = "all-apis"
)
warehouse <- Sys.getenv("DATABRICKS_WAREHOUSE_ID")
sql <- Sys.getenv("APP_SQL", "SELECT current_user() AS user")
volume_file <- Sys.getenv("APP_VOLUME_FILE")

read_data <- function(source, host, token, warehouse, sql, volume_file) {
  switch(
    source,
    sql = brickster::db_sql_query(
      warehouse_id = warehouse,
      statement = sql,
      host = host,
      token = token,
      disposition = "INLINE",
      row_limit = 100,
      show_progress = FALSE
    ),
    dbi = {
      con <- DBI::dbConnect(
        brickster::DatabricksSQL(),
        warehouse_id = warehouse,
        host = host,
        token = token,
        disposition = "INLINE",
        show_progress = FALSE
      )
      on.exit(DBI::dbDisconnect(con))
      DBI::dbGetQuery(con, sql, row_limit = 100)
    },
    catalogs = {
      catalogs <- brickster::db_list_all_pages(
        brickster::db_uc_catalogs_list,
        host = host,
        token = token
      )
      tibble::tibble(name = purrr::map_chr(catalogs, "name"))
    },
    volume = {
      if (!nzchar(volume_file)) {
        stop("Set APP_VOLUME_FILE to a CSV file in a volume.")
      }
      path <- fs::file_temp(ext = "csv")
      on.exit(fs::file_delete(path))
      brickster::db_volume_read(
        volume_file,
        path,
        host = host,
        token = token,
        progress = FALSE
      )
      utils::read.csv(path, nrows = 100)
    }
  )
}

ui <- db_shiny_ui(
  "auth",
  config,
  fluidPage(
    titlePanel("Databricks data"),
    actionButton("login", "Sign in"),
    actionButton("logout", "Sign out"),
    textOutput("user"),
    selectInput(
      "source",
      "Read data using",
      c(
        "SQL query" = "sql",
        "DBI query" = "dbi",
        "Unity Catalog" = "catalogs",
        "Volume CSV" = "volume"
      )
    ),
    bslib::input_task_button("load", "Load data"),
    tableOutput("data")
  )
)

server <- function(input, output, session) {
  auth <- db_shiny_server("auth", config, auto_redirect = FALSE)
  query <- db_shiny_task(auth, read_data, button = "load")
  loaded_source <- reactiveVal(NULL)

  observeEvent(input$login, auth$login(), ignoreInit = TRUE)
  observeEvent(input$logout, auth$logout(), ignoreInit = TRUE)
  observeEvent(
    input$load,
    {
      if (
        query$invoke(
          source = input$source,
          warehouse = warehouse,
          sql = sql,
          volume_file = volume_file
        )
      ) {
        loaded_source(input$source)
      }
    },
    ignoreInit = TRUE
  )

  output$user <- renderText({
    if (!auth$ready()) {
      return("Sign in to load your Databricks data.")
    }
    claims <- auth$identity()$id_token_claims
    paste("Signed in:", if (is.null(claims$email)) claims$sub else claims$email)
  })
  output$data <- renderTable({
    req(identical(loaded_source(), input$source))
    head(query$result(), 100)
  })
}

shinyApp(
  ui,
  server,
  uiPattern = ".*",
  options = list(host = "127.0.0.1", port = 8080)
)
