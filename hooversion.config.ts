export default {
  branches: ["main"],
  packages: [
    {
      name: "hooray",
      path: ".",
      type: "rust",
      manifest: "Cargo.toml",
      changelog: "CHANGELOG.md",
      scopes: ["hooray"],
      dependencies: [],
    },
  ],
  hooks: {
    afterVersion: ["cargo generate-lockfile"],
  },
  github: {
    releases: true,
  },
};
