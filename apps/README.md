# Apps assembly

Surface applications consume the same constitutional core and engine assembly.

## Standalone concept previews

Open the hosted previews:

- [All previews](https://maurits-pixe.github.io/palaco-genesis/)
- [PALACO Web](https://maurits-pixe.github.io/palaco-genesis/palaco-web/)
- [RIO Web](https://maurits-pixe.github.io/palaco-genesis/rio-web/)
- [RIO Mobile](https://maurits-pixe.github.io/palaco-genesis/rio-mobile/)

GitHub Pages publishes this directory through [the preview workflow](../.github/workflows/previews.yml) after changes reach `main` or `master`. The repository's Pages source must be set to **GitHub Actions** under Settings → Pages. To preview before deployment, serve this directory with a local static web server.

For local RIO message sending, run the [RIO message service](../services/rio-messaging/README.md) and use its preview URLs. The hosted Pages previews are visual-only. Shared styling lives in [`preview.css`](preview.css); no preview establishes identity, authority, or live status.
