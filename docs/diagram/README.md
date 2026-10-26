# Architecture diagram

`docs/architecture.svg` is generated; edit the source here instead.

1. Edit `architecture.archify.json` (an [Archify](https://github.com/tt-a1i/archify)
   architecture spec) and render it:

   ```bash
   archify deliver architecture architecture.archify.json architecture.html --quality showcase
   ```

2. Open `architecture.html`, choose **Export → SVG** and save it as `architecture-raw.svg`.
3. Apply the zone styling (green LOCAL, orange CLOUD, no grid, one SVG for light and dark):

   ```bash
   python3 postprocess.py architecture-raw.svg ../architecture.svg
   ```
