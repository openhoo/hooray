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
  github: {
    releases: true,
  },
};
