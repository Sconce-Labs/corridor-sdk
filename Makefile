.PHONY: install test typecheck fmt build docs fixture
install:   ; npm ci
test:      ; npm test
typecheck: ; npm run typecheck
fmt:       ; npm run format
build:     ; npm run build
docs:      ; npm run docs
fixture:   ; npm run gen-fixture
