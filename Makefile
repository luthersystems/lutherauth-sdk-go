.PHONY:print-go-env
print-go-env:
	env
	go env

.PHONY: go-test
go-test:
	go test -v -count 1 ./...

.PHONY: citest
citest: print-go-env go-test
	@
