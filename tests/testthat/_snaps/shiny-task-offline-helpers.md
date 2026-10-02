# current operation failures are exposed and old successful results are hidden

    Code
      query$result()
    Condition
      Error:
      ! Warehouse permission denied

# tasks reject credential overrides and use from another session

    Code
      query$invoke(token = "another-user")
    Condition
      Error in `query$invoke()`:
      ! The task supplies `host` and `token`; pass only operation arguments.

---

    Code
      query$invoke()
    Condition
      Error in `check_session()`:
      ! Use this task in its owning Shiny session.

---

    Code
      query$result()
    Condition
      Error in `check_session()`:
      ! Use this task in its owning Shiny session.

