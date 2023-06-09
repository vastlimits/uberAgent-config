
[comment]: # (BADGE_SECTION_START)

![branch](https://img.shields.io/badge/branch-B792--SMBv1--fix-blue) ![transpilation](https://img.shields.io/badge/MSI%20transpilation-15%20success%2C%200%20failed%2C%2015%20processed-green) ![syntax check](https://img.shields.io/badge/MSI%20syntax%20check-0%20errors%2C%200%20warnings%2C%200%20notes-green)

[comment]: # (BADGE_SECTION_END)

# uberAgent Configuration

This repository is the home for the [uberAgent](https://uberagent.com/) configuration. This repository contains UXM configuration settings (timers, metrics, etc.) as well as ESA Activity Monitoring detection rules and Modular Security Inventory tests.

## Getting Started

1. Select the Git branch that matches your installed uberAgent version.
2. Clone this repository to your machine.
3. Update the files in your [uberAgent configuration](https://uberagent.com/docs/uberagent/latest/planning/configuration-options/) with the files from the `config` or `config-dist` folders of this repository, depending on your uberAgent version (see below).

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

## Help and Support

Please see the [uberAgent documentation portal](https://uberagent.com/docs/) for docs, help and support options.
