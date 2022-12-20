# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [1.2.0] 2022-12-20

### Added

- Allow PEM certificates to be read as public keys ([#19](https://github.com/rib/jsonwebtokens/pull/19))

### Changed

- A verifier with no associated `kid` will allow any token `kid` (like a wildcard) instead of requiring there to be no `kid`. This is a fix that's consistent with the original API documentation ([#18](https://github.com/rib/jsonwebtokens/pull/18))


## [1.1.0] 2021-08-15

### Added

- Allow string _or_ array `aud` claims (previously just allowed string `aud`) ([#13](https://github.com/rib/jsonwebtokens/issues/13))

### Removed

- Spurious assertion that any empty claim key `""` must have a string value