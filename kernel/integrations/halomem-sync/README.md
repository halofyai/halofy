# Halofy Sync for Obsidian

This community-plugin package implements Halofy's user-authorized, one-way
Obsidian connector. It reads selected Markdown files through Obsidian's Vault
and Metadata Cache APIs and sends signed changes to the paired Halofy source.

It never reads filesystem paths directly, never asks for an Obsidian account,
and does not send `.obsidian`, hidden folders, trash, plugins, settings, or
binary attachments. The pairing signing secret is stored through Obsidian's
`SecretStorage`; plugin settings contain only its secret ID.

## Development build

```sh
npm ci
npm run typecheck
npm run build
```

## Manual install

Until Halofy Sync is available in Obsidian's community-plugin directory:

1. Download `manifest.json`, `versions.json`, and `main.js` from this folder.
2. Put all three files in `<vault>/.obsidian/plugins/halomem-sync/`.
3. Restart Obsidian, open **Settings → Community plugins**, and enable
   **Halofy Sync**.
4. In Halofy **Sources → Obsidian**, create a pairing and copy the one-time
   bundle.
5. In Obsidian, open **Settings → Halofy Sync**, paste the bundle, and choose
   **Pair & sync**.

Halofy shows the source as **Awaiting Obsidian** until that first signed sync
finishes. It changes to **Connected** only after Halofy receives vault data.

The plugin ID intentionally does not contain the reserved word `obsidian`, as
required by the Obsidian community-plugin submission rules.
