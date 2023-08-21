# uberAgent Configuration

This repository is the home for the [uberAgent](https://uberagent.com/) configuration. This repository contains UXM configuration settings (timers, metrics, etc.) as well as ESA Threat Detection rules and Security & Compliance Inventory tests.

## Getting Started

1. Select the Git branch that matches your installed uberAgent version.
2. Clone this repository to your machine.
3. Update the files in your [uberAgent configuration](https://uberagent.com/docs/uberagent/latest/planning/configuration-options/) 
   - Choose either the files from the `config` or `config-dist` folders of this repository, depending on your uberAgent version (see [uberAgent Versions & Git Branches](#uberagent-versions--git-branches)).
   - The process can be automated. See [uberAgent Configuration Update Automation](#automating-uberagent-configuration-updates).

## Repository Structure

### uberAgent Versions & Git Branches

This repository is organized in such a way that uberAgent releases are represented by Git branches. Each Git branch contains rules that are compatible with the matching uberAgent release.

| uberAgent version | Git branch |
| ------- | --------------------- |
| `development (beta)` | [develop](../../tree/develop) |
| `7.0.x` | [version/7.0](../../tree/version/7.0) |
| `6.2.x` | [version/6.2](../../tree/version/6.2) |

### Folder Structure

| Folder        | Description                                                  |
| ------------- | ------------------------------------------------------------ |
| `config`      | Compiled configuration as individual source files. Use the contents of this folder for your **deployment with any uberAgent version**. |
| `config-dev`  | Contains files that cannot be used without further processing, such as transpilation. Do not use the contents of this folder on your endpoints unless you know what you're doing. |
| `config-dist` | Compiled configuration as configuration archive (`*.uAConfig`). Use the contents of this folder for your **deployment with uberAgent 7.1+**. |

## Automating uberAgent Configuration Updates

While the configuration for uberAgent UXM remains relatively static, the configuration for uberAgent ESA changes daily due to regular updates to the included Sigma rules.

To make your life easier, we provide a PowerShell script that automates the configuration file pulling, filtering, and bundling. You can find more information in [Tools/InvokeuberAgentConfigDownload](Tools/InvokeuberAgentConfigDownload).

## Help and Support

Please see the [uberAgent documentation portal](https://uberagent.com/docs/) for docs, help and support options.
