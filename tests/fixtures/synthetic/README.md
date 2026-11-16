# Synthetic fixtures

This directory is reserved. Test captures are generated at test time by
`tools/fixturegen/` into the build tree (`build/<type>/fixtures/`) and are never
committed. A capture file may be stored here only in the exceptional case that it
cannot be generated, and it must be synthetic. The leak guard
(`tools/check-no-captures.sh`) rejects captures anywhere else in the repository.
