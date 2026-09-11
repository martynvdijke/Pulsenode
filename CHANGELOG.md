## [1.30.4](https://github.com/martynvdijke/synapse/compare/v1.30.3...v1.30.4) (2026-09-11)

## [1.30.3](https://github.com/martynvdijke/synapse/compare/v1.30.2...v1.30.3) (2026-09-10)

## [1.30.2](https://github.com/martynvdijke/synapse/compare/v1.30.1...v1.30.2) (2026-09-09)


### Bug Fixes

* **deps:** update all non-major dependencies ([#53](https://github.com/martynvdijke/synapse/issues/53)) ([90a8d67](https://github.com/martynvdijke/synapse/commit/90a8d673293f2757166ca97ac03a2cc046192394))

## [1.30.1](https://github.com/martynvdijke/synapse/compare/v1.30.0...v1.30.1) (2026-09-08)


### Bug Fixes

* **deps:** update module golang.org/x/oauth2 to v0.37.0 ([#52](https://github.com/martynvdijke/synapse/issues/52)) ([84e657a](https://github.com/martynvdijke/synapse/commit/84e657ae2471e4f697431fd7a63d44005c814efb))

# [1.30.0](https://github.com/martynvdijke/synapse/compare/v1.29.4...v1.30.0) (2026-09-08)


### Features

* **auth:** add Authelia OIDC login with session-or-token mutation auth ([65703a9](https://github.com/martynvdijke/synapse/commit/65703a9a3295ed38dabbf6c21b92f2996f77800a))

## [1.29.4](https://github.com/martynvdijke/synapse/compare/v1.29.3...v1.29.4) (2026-09-07)

## [1.29.3](https://github.com/martynvdijke/synapse/compare/v1.29.2...v1.29.3) (2026-09-05)


### Bug Fixes

* **deps:** update all non-major dependencies ([#50](https://github.com/martynvdijke/synapse/issues/50)) ([4566664](https://github.com/martynvdijke/synapse/commit/4566664216874b0b1e27453be10f8b19d8477178))

## [1.29.2](https://github.com/martynvdijke/synapse/compare/v1.29.1...v1.29.2) (2026-09-02)

## [1.29.1](https://github.com/martynvdijke/synapse/compare/v1.29.0...v1.29.1) (2026-08-31)


### Bug Fixes

* **deps:** update all non-major dependencies ([297e2aa](https://github.com/martynvdijke/synapse/commit/297e2aaf21cd6b3c0a58a61fa012630903a4a21f))

# [1.29.0](https://github.com/martynvdijke/synapse/compare/v1.28.2...v1.29.0) (2026-08-31)


### Features

* **board:** add public Homer-like overview page ([f8682d5](https://github.com/martynvdijke/synapse/commit/f8682d58b0a71f01afa3873d516418dfa726c976))

## [1.28.2](https://github.com/martynvdijke/synapse/compare/v1.28.1...v1.28.2) (2026-08-30)

## [1.28.1](https://github.com/martynvdijke/synapse/compare/v1.28.0...v1.28.1) (2026-08-28)


### Bug Fixes

* **ci:** correct actionlint pin ([d4b1a69](https://github.com/martynvdijke/synapse/commit/d4b1a699cb07e37e8773ded481d44719ef70d2f4))
* **ci:** make pinact check non-blocking ([e3b98e7](https://github.com/martynvdijke/synapse/commit/e3b98e768f7a03919a06caaee995d1dacda8b789))
* **ci:** remove unsupported --diff flag from pinact ([5aa1a8b](https://github.com/martynvdijke/synapse/commit/5aa1a8b0b8ddc80fa94a21383ac3cb10da39ebc5))
* **ci:** update actionlint to v1.7.12 (v1 tag removed upstream) ([8f90d29](https://github.com/martynvdijke/synapse/commit/8f90d298e95e6ba97cdffd7b44ea95ae70cac9dc))

# [1.28.0](https://github.com/martynvdijke/synapse/compare/v1.27.0...v1.28.0) (2026-08-26)


### Features

* **settings:** make persistent notification optional ([4ec3779](https://github.com/martynvdijke/synapse/commit/4ec37795d663558cb49081393cdf4ad6c5cd12f9))

# [1.27.0](https://github.com/martynvdijke/synapse/compare/v1.26.2...v1.27.0) (2026-08-24)


### Features

* **trmnl:** alerts and events screens with per-screen lint/push ([f63af41](https://github.com/martynvdijke/synapse/commit/f63af41546b6dd53b471146417f3e063d84d12c4))

## [1.26.2](https://github.com/martynvdijke/synapse/compare/v1.26.1...v1.26.2) (2026-08-24)


### Bug Fixes

* **kuma:** auto-resolve valid docker_host id to prevent FK constraint failure ([a18759e](https://github.com/martynvdijke/synapse/commit/a18759e8ca99b4bd5f5ec499eb9fab2e368dfe52))

## [1.26.1](https://github.com/martynvdijke/synapse/compare/v1.26.0...v1.26.1) (2026-08-24)


### Bug Fixes

* **kuma:** always send string-array accepted_statuscodes and read monitorID ack field ([b0f0117](https://github.com/martynvdijke/synapse/commit/b0f011725d5688a320291d77a6f289d6d1b5726d))

# [1.26.0](https://github.com/martynvdijke/synapse/compare/v1.25.0...v1.26.0) (2026-08-22)


### Features

* **kuma:** monitor lifecycle with pause/resume, tags, and reconcile skip ([a372d4f](https://github.com/martynvdijke/synapse/commit/a372d4f0df02cbbed557c4f9d40085d53ce8b82d))

# [1.25.0](https://github.com/martynvdijke/synapse/compare/v1.24.0...v1.25.0) (2026-08-22)


### Features

* **alerts:** dashboard Alerts tab with rules editor, incidents, and status counts ([6fa2c68](https://github.com/martynvdijke/synapse/commit/6fa2c68e12af0d880a306edc11f813db825894e7))

# [1.24.0](https://github.com/martynvdijke/synapse/compare/v1.23.0...v1.24.0) (2026-08-22)


### Features

* **alerts:** rule evaluation engine with incident lifecycle and notifier wiring ([ec35324](https://github.com/martynvdijke/synapse/commit/ec3532415a09a8004c85520226d9de15c93a607f))

# [1.23.0](https://github.com/martynvdijke/synapse/compare/v1.22.0...v1.23.0) (2026-08-22)


### Features

* **alerts:** rule CRUD and incident lifecycle API with tests ([37caf18](https://github.com/martynvdijke/synapse/commit/37caf18a1ad53c6722a565fab612526baff7c502))

# [1.22.0](https://github.com/martynvdijke/synapse/compare/v1.21.0...v1.22.0) (2026-08-22)


### Features

* **alerts:** wire alert settings through env config, settings API, and notifier toggles ([6820d55](https://github.com/martynvdijke/synapse/commit/6820d55d17e977f951650fb232094effb1f4d034))

# [1.21.0](https://github.com/martynvdijke/synapse/compare/v1.20.0...v1.21.0) (2026-08-22)


### Features

* **notify:** fan out alerts to multi-channel notifiers (ntfy, Telegram, Discord, webhooks) ([16401fe](https://github.com/martynvdijke/synapse/commit/16401fe2697d216bda617a88095685b16dee4b3a))

# [1.20.0](https://github.com/martynvdijke/synapse/compare/v1.19.2...v1.20.0) (2026-08-20)


### Features

* **tabs:** make dashboard tabs configurable ([f310283](https://github.com/martynvdijke/synapse/commit/f3102834714851f0ff128bd83153a0f8f679384e))

## [1.19.2](https://github.com/martynvdijke/synapse/compare/v1.19.1...v1.19.2) (2026-08-20)


### Bug Fixes

* **notify:** treat service-linked items as covered in missing-from-Kuma check ([2b02e6d](https://github.com/martynvdijke/synapse/commit/2b02e6ded86a0db19631b311afc02f6ec7016de5))


### Performance Improvements

* **links:** parallelize link editor load and cache link targets ([be114f1](https://github.com/martynvdijke/synapse/commit/be114f1e1131b6c52009a838e2d45559ab0c9200))

## [1.19.1](https://github.com/martynvdijke/synapse/compare/v1.19.0...v1.19.1) (2026-08-20)

# [1.19.0](https://github.com/martynvdijke/synapse/compare/v1.18.1...v1.19.0) (2026-08-19)


### Features

* **api:** require bearer tokens for mutations and add token lifecycle ([2bb1162](https://github.com/martynvdijke/synapse/commit/2bb116228ffcb1ea116857cbed2aa390bdd622e4))

## [1.18.1](https://github.com/martynvdijke/synapse/compare/v1.18.0...v1.18.1) (2026-08-19)


### Performance Improvements

* **dashboard:** speed up UI load with caching, parallel health checks and gzip ([6267266](https://github.com/martynvdijke/synapse/commit/62672669c93415186ff0cc270bf37c7ed52be46b))

# [1.18.0](https://github.com/martynvdijke/synapse/compare/v1.17.5...v1.18.0) (2026-08-18)


### Features

* **links:** complete service linking UI with NPM, Kuma and Authelia ([b9461bc](https://github.com/martynvdijke/synapse/commit/b9461bc2223997c667c9cbd354e410b3ef16926d))

## [1.17.5](https://github.com/martynvdijke/synapse/compare/v1.17.4...v1.17.5) (2026-08-18)


### Bug Fixes

* **deps:** update all non-major dependencies ([c78008e](https://github.com/martynvdijke/synapse/commit/c78008e794b5ec6abd8fb3ab22b72cd92d803fb5))
* **kuma:** synchronize onEvent handoff to fix data race ([0aa3b6c](https://github.com/martynvdijke/synapse/commit/0aa3b6c1fade40378e4393ad2e6e44bf1078d36a))

## [1.17.4](https://github.com/martynvdijke/synapse/compare/v1.17.3...v1.17.4) (2026-08-16)


### Bug Fixes

* **trmnl:** fix stats data binding and layout width ([610f636](https://github.com/martynvdijke/synapse/commit/610f636839a04e3a089adcbe9e7b1f83d2a85845))

## [1.17.3](https://github.com/martynvdijke/synapse/compare/v1.17.2...v1.17.3) (2026-08-15)


### Bug Fixes

* **trmnl:** pin plugin ID and gate trmnlp push on release ([5ec7e7c](https://github.com/martynvdijke/synapse/commit/5ec7e7c64e9c3493b6094f3ff8d83d0d73253ba4))

## [1.17.2](https://github.com/martynvdijke/synapse/compare/v1.17.1...v1.17.2) (2026-08-15)


### Bug Fixes

* **kuma:** fall back to HTTP long-polling when WebSocket dial fails ([01c1fe6](https://github.com/martynvdijke/synapse/commit/01c1fe60ff7c7d86ea4446043c4ad95ed36e0661))

## [1.17.1](https://github.com/martynvdijke/synapse/compare/v1.17.0...v1.17.1) (2026-08-15)


### Bug Fixes

* **test:** kuma login ack echoes client ack id ([1916b36](https://github.com/martynvdijke/synapse/commit/1916b36fcdf6601d66672fd2cf758465033365ad))

# [1.17.0](https://github.com/martynvdijke/synapse/compare/v1.16.0...v1.17.0) (2026-08-15)


### Features

* **links:** service-to-NPM/Kuma linking, monitor and proxy host management ([dbe7cee](https://github.com/martynvdijke/synapse/commit/dbe7cee2c42ee29fc74e005718272a16ce146070))

# [1.16.0](https://github.com/martynvdijke/synapse/compare/v1.15.0...v1.16.0) (2026-08-13)


### Features

* **ui:** events tab, reconcile control and settings ([44a5d9c](https://github.com/martynvdijke/synapse/commit/44a5d9c6aaa74595bb2c7333827ea06d7284c9d0))

# [1.15.0](https://github.com/martynvdijke/synapse/compare/v1.14.0...v1.15.0) (2026-08-13)


### Features

* **api:** reconcile and docker event endpoints ([a9cdf55](https://github.com/martynvdijke/synapse/commit/a9cdf55281b93f9103f9ecd4a6e5aeec5cb8d652))

# [1.14.0](https://github.com/martynvdijke/synapse/compare/v1.13.0...v1.14.0) (2026-08-13)


### Features

* add ServiceLink + DockerEvent entities and reconciliation settings ([3e97496](https://github.com/martynvdijke/synapse/commit/3e9749677850a4ee973e1cdddda6602c7e6ca88a))
* **docker:** minimal Docker Engine client with event watcher ([23c5db9](https://github.com/martynvdijke/synapse/commit/23c5db9586ff617e50f9a4e23ce7334a4ce9981b))
* **kuma:** delete and edit monitors via Socket.IO ([9061d48](https://github.com/martynvdijke/synapse/commit/9061d4858c5fc972d389a7c3bac3c18ef877b39e))
* **notify:** EventNotifier with per-category toggles and cooldown dedup ([600fe37](https://github.com/martynvdijke/synapse/commit/600fe37b70f876c2869652f2357b9f7b3b433991))
* **npm:** full proxy host details, create and update ([52fb857](https://github.com/martynvdijke/synapse/commit/52fb8579a1b0750206d0327ef36458a3b9c0b80f))
* **sync:** reconciliation engine over service links ([35514bf](https://github.com/martynvdijke/synapse/commit/35514bfb63cd87851fe58a2eda18197aac614750))

# [1.13.0](https://github.com/martynvdijke/synapse/compare/v1.12.4...v1.13.0) (2026-08-13)


### Bug Fixes

* parse flattened NPM proxy host responses ([8481c2d](https://github.com/martynvdijke/synapse/commit/8481c2d57fc4436e1a0d389c4e10578c791dfe34))


### Features

* recurrent Gotify notifications for items missing from Uptime Kuma ([6e827de](https://github.com/martynvdijke/synapse/commit/6e827de68f074a8c580a311c1b596bc871d43641))

## [1.12.4](https://github.com/martynvdijke/synapse/compare/v1.12.3...v1.12.4) (2026-08-11)


### Bug Fixes

* show live Kuma monitor count on dashboard ([60e9691](https://github.com/martynvdijke/synapse/commit/60e9691efecc6ba95b5630403de34353cf9aa1fc))

## [1.12.3](https://github.com/martynvdijke/synapse/compare/v1.12.2...v1.12.3) (2026-08-09)


### Bug Fixes

* parse numeric uptime durations from Kuma ([7619c43](https://github.com/martynvdijke/synapse/commit/7619c43787d39f2748bdaaeee422aaa0b05cdde8))

## [1.12.2](https://github.com/martynvdijke/synapse/compare/v1.12.1...v1.12.2) (2026-08-09)


### Bug Fixes

* parse monitorList, cache queries, and cut Kuma collection to 5s ([05e836a](https://github.com/martynvdijke/synapse/commit/05e836acb1ea39aaaa9be691e42fffb71002cd37))

## [1.12.1](https://github.com/martynvdijke/synapse/compare/v1.12.0...v1.12.1) (2026-08-09)


### Bug Fixes

* use socket.io protocol v5 ack format for Kuma login ([9310122](https://github.com/martynvdijke/synapse/commit/9310122dfd35ed52e537752f56a4e32823a1c301))

# [1.12.0](https://github.com/martynvdijke/synapse/compare/v1.11.2...v1.12.0) (2026-08-08)


### Features

* add TRMNL stats display plugin ([ee7dba8](https://github.com/martynvdijke/synapse/commit/ee7dba80f657bd3b08c98b57c98c1961d7e95df2))

## [1.11.2](https://github.com/martynvdijke/synapse/compare/v1.11.1...v1.11.2) (2026-08-08)

## [1.11.1](https://github.com/martynvdijke/synapse/compare/v1.11.0...v1.11.1) (2026-08-07)

# [1.11.0](https://github.com/martynvdijke/synapse/compare/v1.10.0...v1.11.0) (2026-08-07)


### Features

* add e-ink mode for e-paper displays ([25555eb](https://github.com/martynvdijke/synapse/commit/25555ebe77b5e7f95d64cecc3e144be783e06a21)), closes [Hi#contrast](https://github.com/Hi/issues/contrast)

# [1.10.0](https://github.com/martynvdijke/synapse/compare/v1.9.24...v1.10.0) (2026-08-07)


### Features

* complete OTel observability — metrics, logs, and DB query tracing ([77a868e](https://github.com/martynvdijke/synapse/commit/77a868ee6edf31e7cbcbcb27ec66061d33fbb4ae))

## [1.9.24](https://github.com/martynvdijke/synapse/compare/v1.9.23...v1.9.24) (2026-08-05)


### Bug Fixes

* **deps:** update all non-major dependencies to v0.70.0 ([#41](https://github.com/martynvdijke/synapse/issues/41)) ([32fce71](https://github.com/martynvdijke/synapse/commit/32fce710bad8f5386ed699b2f901346587b2665c))

## [1.9.23](https://github.com/martynvdijke/synapse/compare/v1.9.22...v1.9.23) (2026-08-04)


### Bug Fixes

* **deps:** update all non-major dependencies to v1.45.0 ([#40](https://github.com/martynvdijke/synapse/issues/40)) ([90a8420](https://github.com/martynvdijke/synapse/commit/90a842010258a51f4e162134080ebc14351be67e))

## [1.9.22](https://github.com/martynvdijke/synapse/compare/v1.9.21...v1.9.22) (2026-08-03)

## [1.9.21](https://github.com/martynvdijke/synapse/compare/v1.9.20...v1.9.21) (2026-07-31)

## [1.9.20](https://github.com/martynvdijke/synapse/compare/v1.9.19...v1.9.20) (2026-07-30)

## [1.9.19](https://github.com/martynvdijke/synapse/compare/v1.9.18...v1.9.19) (2026-07-30)

## [1.9.18](https://github.com/martynvdijke/synapse/compare/v1.9.17...v1.9.18) (2026-07-29)


### Bug Fixes

* **deps:** update module github.com/mattn/go-sqlite3 to v1.14.49 ([#35](https://github.com/martynvdijke/synapse/issues/35)) ([9778e82](https://github.com/martynvdijke/synapse/commit/9778e8204d750c6ccab9db0ec068c38f6d531b7e))

## [1.9.17](https://github.com/martynvdijke/synapse/compare/v1.9.16...v1.9.17) (2026-07-28)

## [1.9.16](https://github.com/martynvdijke/synapse/compare/v1.9.15...v1.9.16) (2026-07-27)

## [1.9.15](https://github.com/martynvdijke/synapse/compare/v1.9.14...v1.9.15) (2026-07-26)

## [1.9.14](https://github.com/martynvdijke/synapse/compare/v1.9.13...v1.9.14) (2026-07-25)

## [1.9.13](https://github.com/martynvdijke/synapse/compare/v1.9.12...v1.9.13) (2026-07-20)

## [1.9.12](https://github.com/martynvdijke/synapse/compare/v1.9.11...v1.9.12) (2026-07-17)

## [1.9.11](https://github.com/martynvdijke/synapse/compare/v1.9.10...v1.9.11) (2026-07-16)

## [1.9.10](https://github.com/martynvdijke/synapse/compare/v1.9.9...v1.9.10) (2026-07-13)


### Bug Fixes

* **deps:** update all non-major dependencies ([#27](https://github.com/martynvdijke/synapse/issues/27)) ([36c68d3](https://github.com/martynvdijke/synapse/commit/36c68d3ff28c0e9c2b16d59ea303d1919d558fdd))

## [1.9.9](https://github.com/martynvdijke/synapse/compare/v1.9.8...v1.9.9) (2026-07-09)


### Bug Fixes

* **deps:** update all non-major dependencies ([#26](https://github.com/martynvdijke/synapse/issues/26)) ([8cbd92f](https://github.com/martynvdijke/synapse/commit/8cbd92f4f785652dc223b679eec85f0fe50f9444))

## [1.9.8](https://github.com/martynvdijke/synapse/compare/v1.9.7...v1.9.8) (2026-07-09)

## [1.9.7](https://github.com/martynvdijke/synapse/compare/v1.9.6...v1.9.7) (2026-07-08)

## [1.9.6](https://github.com/martynvdijke/synapse/compare/v1.9.5...v1.9.6) (2026-07-06)


### Bug Fixes

* rewrite NPM and Kuma auth to match upstream APIs ([ce07f59](https://github.com/martynvdijke/synapse/commit/ce07f5984764165ac917c89955e469c58943738c))

## [1.9.5](https://github.com/martynvdijke/synapse/compare/v1.9.4...v1.9.5) (2026-07-06)

## [1.9.4](https://github.com/martynvdijke/synapse/compare/v1.9.3...v1.9.4) (2026-07-02)

## [1.9.3](https://github.com/martynvdijke/synapse/compare/v1.9.2...v1.9.3) (2026-07-01)

## [1.9.2](https://github.com/martynvdijke/synapse/compare/v1.9.1...v1.9.2) (2026-06-30)

## [1.9.1](https://github.com/martynvdijke/synapse/compare/v1.9.0...v1.9.1) (2026-06-29)

# [1.9.0](https://github.com/martynvdijke/synapse/compare/v1.8.0...v1.9.0) (2026-06-26)


### Features

* complete authelia-multi-decouple ([bff861b](https://github.com/martynvdijke/synapse/commit/bff861bc79c37258527c24eeee0572ac36847cd2))

# [1.8.0](https://github.com/martynvdijke/synapse/compare/v1.7.0...v1.8.0) (2026-06-26)


### Features

* add AutheliaInstance data model + ent schema + db CRUD + migration ([8b9f950](https://github.com/martynvdijke/synapse/commit/8b9f950ab938b2df718d6c1ddb3d6e68af3ab006))

# [1.7.0](https://github.com/martynvdijke/synapse/compare/v1.6.0...v1.7.0) (2026-06-26)


### Features

* complete npm-multi-instance with tests, typescript conversion ([5ac2162](https://github.com/martynvdijke/synapse/commit/5ac2162eed4f1da8ef9cbab9527dc778c108b8f2))

# [1.6.0](https://github.com/martynvdijke/synapse/compare/v1.5.6...v1.6.0) (2026-06-25)


### Features

* add NPM multi-instance support (schema, client, registry, API handlers, sync fan-out) ([c5f383f](https://github.com/martynvdijke/synapse/commit/c5f383f8a5e230a02338059f558a8d1b5f7dff50))

## [1.5.6](https://github.com/martynvdijke/synapse/compare/v1.5.5...v1.5.6) (2026-06-25)


### Bug Fixes

* refactor KumaMonitors handler to use kumaRegistry + REST, add on-demand stats endpoint ([4959539](https://github.com/martynvdijke/synapse/commit/49595399b45ae443e80a42a1de4e06dd2bd6c48f))

## [1.5.5](https://github.com/martynvdijke/synapse/compare/v1.5.4...v1.5.5) (2026-06-24)

## [1.5.4](https://github.com/martynvdijke/synapse/compare/v1.5.3...v1.5.4) (2026-06-23)

## [1.5.3](https://github.com/martynvdijke/synapse/compare/v1.5.2...v1.5.3) (2026-06-22)


### Bug Fixes

* **deps:** update all non-major dependencies ([#16](https://github.com/martynvdijke/synapse/issues/16)) ([0f32a75](https://github.com/martynvdijke/synapse/commit/0f32a75c2ff62a1157e649c6fb7ca052f8207b59))

## [1.5.2](https://github.com/martynvdijke/synapse/compare/v1.5.1...v1.5.2) (2026-06-19)

## [1.5.1](https://github.com/martynvdijke/synapse/compare/v1.5.0...v1.5.1) (2026-06-18)


### Bug Fixes

* **deps:** update all non-major dependencies to v1.14.46 ([#14](https://github.com/martynvdijke/synapse/issues/14)) ([2bc5399](https://github.com/martynvdijke/synapse/commit/2bc5399947b3fcfba8684100b4584b9d5dfc4975))

# [1.5.0](https://github.com/martynvdijke/synapse/compare/v1.4.1...v1.5.0) (2026-06-17)


### Features

* support multiple Uptime Kuma instances and clickable Docker card ([d77b092](https://github.com/martynvdijke/synapse/commit/d77b09218aef598fc0420bd35160b09177f79714))

## [1.4.1](https://github.com/martynvdijke/synapse/compare/v1.4.0...v1.4.1) (2026-06-17)


### Bug Fixes

* handle all Docker Compose YAML format variants in ServiceDef parsing ([97e905c](https://github.com/martynvdijke/synapse/commit/97e905c60c2c5ec3c72499eeb184e460abae4c04))

# [1.4.0](https://github.com/martynvdijke/synapse/compare/v1.3.3...v1.4.0) (2026-06-16)


### Bug Fixes

* preserve compose_path on save, fix skip-link, add SaveSettingsMap tests ([abb3d14](https://github.com/martynvdijke/synapse/commit/abb3d1481c4855098bfc5edcd99ac2ae7704fccf))


### Features

* improve compose metadata parsing, connection logging, and health indicators ([bde46cf](https://github.com/martynvdijke/synapse/commit/bde46cf3438bb226c4c10886c85f6f52f4e4605c))

## [1.3.3](https://github.com/martynvdijke/synapse/compare/v1.3.2...v1.3.3) (2026-06-15)

## [1.3.2](https://github.com/martynvdijke/synapse/compare/v1.3.1...v1.3.2) (2026-06-15)

## [1.3.1](https://github.com/martynvdijke/synapse/compare/v1.3.0...v1.3.1) (2026-06-14)


### Bug Fixes

* default DB_PATH to /db/synapse.db so volume mounts work correctly ([7d299f0](https://github.com/martynvdijke/synapse/commit/7d299f048e5efc505deee28db3d3a714182ff2c8))

# [1.3.0](https://github.com/martynvdijke/synapse/compare/v1.2.1...v1.3.0) (2026-06-13)


### Features

* quality and polish improvements ([43b9c70](https://github.com/martynvdijke/synapse/commit/43b9c703dea2eb38cfb03f1eec22721ee5aab019))

## [1.2.1](https://github.com/martynvdijke/synapse/compare/v1.2.0...v1.2.1) (2026-06-12)

# [1.2.0](https://github.com/martynvdijke/synapse/compare/v1.1.4...v1.2.0) (2026-06-11)


### Features

* add central logging tab with external dependency instrumentation ([5a3689f](https://github.com/martynvdijke/synapse/commit/5a3689f5d29a410017c6062070dd25f3cf974cd7))

## [1.1.4](https://github.com/martynvdijke/synapse/compare/v1.1.3...v1.1.4) (2026-06-09)

## [1.1.3](https://github.com/martynvdijke/synapse/compare/v1.1.2...v1.1.3) (2026-06-09)

## [1.1.2](https://github.com/martynvdijke/synapse/compare/v1.1.1...v1.1.2) (2026-06-09)


### Bug Fixes

* **deps:** update all non-major dependencies to v0.53.0 ([#10](https://github.com/martynvdijke/synapse/issues/10)) ([813a69c](https://github.com/martynvdijke/synapse/commit/813a69cc2d53c91790175f5cb9826d6cc1aa7a30))

## [1.1.1](https://github.com/martynvdijke/synapse/compare/v1.1.0...v1.1.1) (2026-06-08)

# [1.1.0](https://github.com/martynvdijke/synapse/compare/v1.0.4...v1.1.0) (2026-06-07)


### Bug Fixes

* add actions:read permission to release workflow ci job for reusable workflow ([8d50dd4](https://github.com/martynvdijke/synapse/commit/8d50dd49a82e29f3361d1570e9146da31b310645))
* invalid timezone UTC+1, use Europe/Amsterdam instead ([73cb8df](https://github.com/martynvdijke/synapse/commit/73cb8dfd667f61d15f05739c1bc07e3f2ffb9f1a))
* remove duplicate otel job from release.yaml (ci.yaml already exports traces when called as reusable workflow) ([706a9fb](https://github.com/martynvdijke/synapse/commit/706a9fb769798664a88daf4e5ac4846583e7a3dd))
* remove stalePr from renovate.json (no longer valid in Renovate v37) ([8cf6e3f](https://github.com/martynvdijke/synapse/commit/8cf6e3f7eed7089f56d11ccf57fb67269990f95c))
* remove stalePrAge from renovate.json (removed in Renovate v37) ([9a604d5](https://github.com/martynvdijke/synapse/commit/9a604d56a7ddcba29dc63de1e3b4c15f613803ec))
* resolve go.mod conflicts after rebase onto main, fix telemetry test signature ([149888e](https://github.com/martynvdijke/synapse/commit/149888e2c0996f6cc447cf13f23e55009ba9295c))
* restore concurrency and permissions on ci job call in release.yaml ([c104f6e](https://github.com/martynvdijke/synapse/commit/c104f6ed44f0622c49d96bc3186472a41e42dae8))
* restore release job to release.yaml, startup_failure was caused by missing permissions on reusable workflow call ([dd496ec](https://github.com/martynvdijke/synapse/commit/dd496ecac7a88a660dea58bc2afe799682626e14))
* revert otel-cicd-action inputs to use githubToken (v4 doesn't accept otlpAuthorization/otelToken) ([ba9dfce](https://github.com/martynvdijke/synapse/commit/ba9dfcece00d54b381ad1b9df6164a31172bebce))
* simplify release.yaml to minimum to isolate startup_failure ([1ea4e43](https://github.com/martynvdijke/synapse/commit/1ea4e435d40c9bff16266ddb24f520863dca2192))
* **ui:** add for/id to form labels, replace inline onclick handlers with addEventListener ([600b7a6](https://github.com/martynvdijke/synapse/commit/600b7a6fe25d67e40d42db0090b73cac39ed1556))


### Features

* add Authelia integration — config sync, alerts, temp access, ban management ([7674489](https://github.com/martynvdijke/synapse/commit/76744896d33a504aeb2b385351868fbc08f1fada))
* add OTel endpoint admin configuration with DB-backed settings ([4da63d9](https://github.com/martynvdijke/synapse/commit/4da63d9d1fdca5b14883eb0a2a497cbaf6acf2ec))
* add otlpAuthorization input for Bearer auth ([f59701d](https://github.com/martynvdijke/synapse/commit/f59701da54f6ce3e53d82635814b54959ffbce11))
* add socketio client for kuma uptime monitoring ([95677d8](https://github.com/martynvdijke/synapse/commit/95677d89c2bab69b2ec4d41d8bfdf11f5f0e406e))
* improve healthcheck parser, add periodic sync scheduler, add client tests ([4903814](https://github.com/martynvdijke/synapse/commit/4903814e731a9db61f6b65d7870041c6d690db53))

## [1.0.4](https://github.com/martynvdijke/synapse/compare/v1.0.3...v1.0.4) (2026-06-07)


### Bug Fixes

* **deps:** update all non-major dependencies to v1.14.45 ([#6](https://github.com/martynvdijke/synapse/issues/6)) ([8ecfb3e](https://github.com/martynvdijke/synapse/commit/8ecfb3e2aab6da995887e870d4fe5398ce11629d))

## [1.0.3](https://github.com/martynvdijke/synapse/compare/v1.0.2...v1.0.3) (2026-06-04)

## [1.0.2](https://github.com/martynvdijke/synapse/compare/v1.0.1...v1.0.2) (2026-05-29)


### Bug Fixes

* **deps:** update all non-major dependencies ([#4](https://github.com/martynvdijke/synapse/issues/4)) ([de57607](https://github.com/martynvdijke/synapse/commit/de5760744aeac6a051b6ae9f4c04920be54feb89))

## [1.0.1](https://github.com/martynvdijke/synapse/compare/v1.0.0...v1.0.1) (2026-05-19)

# 1.0.0 (2026-05-19)


### Features

* add OpenTelemetry tracing instrumentation ([d75ff90](https://github.com/martynvdijke/synapse/commit/d75ff908d6d9115e2ef69e627d3cf3910e664fa0))
* get in there ([a97fcbb](https://github.com/martynvdijke/synapse/commit/a97fcbb9dec9d802d37beebd895ab3c4084cd0e8))
* rewrite into synapse ([26d10d8](https://github.com/martynvdijke/synapse/commit/26d10d8f78287e53db09ab5684d828d338911445))
