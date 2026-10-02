Run this example with a version of brickster containing the Shiny helpers and
development shinyOAuth (0.6.1.9000 or later):

```r
pak::pak("lukakoning/shinyOAuth")
pak::local_install(".")
shiny::runApp("inst/examples/shiny-app", port = 8080)
```

The [Shiny vignette](../../../vignettes/shiny.Rmd) describes OAuth registration
and environment settings and shows the complete app code. The example supports
SQL queries, DBI queries, Unity Catalog listings, and CSV files in volumes.

The initial query displays `current_user()`. Set `APP_SQL` to query your own
table, and `APP_VOLUME_FILE` to enable the volume example. The app uses each
signed-in user's authorization and runs data operations through `ExtendedTask`
and mirai.
