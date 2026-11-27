### Fixed

- The C5 process runner copies each reply's response bytes into a buffer from a per-server pool, prefilled from the case's bounds, inside the application window and returns it once the reply is framed, instead of cloning the response outside every probe window: a reply is the application's output and is now counted with `apply` (karyos#691).
