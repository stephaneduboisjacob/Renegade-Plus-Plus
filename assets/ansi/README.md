# ANSI artwork

**Contact:** Stephane Jacob / [jacobstephane@outlook.com](mailto:jacobstephane@outlook.com)

## Artwork used by the BBS

The default main menu, message-area screens, file-area screens, and live chat now incorporate signed panels from the supplied Roy_EarlyANSI collection:

| Screen | Artwork |
| --- | --- |
| Main menu | `imported/Roy_EarlyANSI/MAINMENU.ANS` |
| Message areas and boards | `imported/Roy_EarlyANSI/MMSMENU.ANS` |
| File areas | `imported/Roy_EarlyANSI/FILEDIR.ANS` |
| Live chat | `imported/Roy_EarlyANSI/CHATMENU.ANS` |

The panels retain the artist's ANSI colors and signature. Renegade++ clears the static menu text below each panel and draws live choices and current keyboard controls in its place. This keeps the artwork while ensuring displayed choices match the running BBS.

The rest of the `renegade/` directory contains screen-specific Renegade++ ANSI panels. Each can be selected with its matching `serve --*-art PATH` option. `--message-art PATH` sets the fallback panel for message screens that do not have a dedicated path.

## Gallery collection

`imported/` contains 1,000 ANSI and ASCII artworks: 393 `.ANS` screens and 607 `.ASC` pieces. `imported/manifest.json` records the source collection path, size, and SHA-256 hash for every file. The files are browseable from the BBS's ANSI/ASCII gallery. Add a new collection with `../tools/import_art.py` into a separate empty destination directory.

See [CREDITS.md](../../CREDITS.md) for the artwork attribution and reuse notice.
