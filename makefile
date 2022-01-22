setup:
	go get

test:
	go test -v ./.

coverage:
	go test -v -coverprofile _coverage.out ./.

covreport:
	go test -v -covermode=count -coverprofile _coverage.out ./.
	go tool cover -html="_coverage.out"

benchmark:
	go test -benchmem -run=^$$ -bench ^Benchmark* ./. > benchmark.out

lint:
	golangci-lint run

vet:
	go vet

clean:
	go mod tidy
	go fmt

check: clean vet lint test coverage