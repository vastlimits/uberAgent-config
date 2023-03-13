# uberAgent Configuration

This repository is the home for the [uberAgent](https://uberagent.com/) configuration. This repository contains UXM configuration settings (timers, metrics, etc.) as well as ESA Activity Monitoring detection rules and Modular Security Inventory tests.

## Getting Started

1. Select the Git branch that matches your installed uberAgent version.
2. Clone this repository to your machine.
3. Update the files in your [uberAgent configuration](https://uberagent.com/docs/uberagent/latest/planning/configuration-options/) with the files from the `config` folder of this repository.

## Repository Structure

### uberAgent Versions & Git Branches

This repository is organized in such a way that uberAgent releases are represented by Git branches. Each Git branch contains rules that are compatible with the matching uberAgent release.

| uberAgent version | Git branch |
| ------- | --------------------- |
| `development (beta)` | [develop](../../tree/develop) |
| `7.0.x` | [version/7.0](../../tree/version/7.0) |
| `6.2.x` | [version/6.2](../../tree/version/6.2) |

### Folder Structure

| Folder       | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `config`     | Compiled configuration. Use the contents of this folder as the starting point for your deployment. |
| `config-dev` | Contains files that cannot be used without further processing, such as transpilation. Do not use the contents of this folder on your endpoints unless you know what you're doing. |

## Help and Support

Please see the [uberAgent documentation portal](https://uberagent.com/docs/) for docs, help and support options.
