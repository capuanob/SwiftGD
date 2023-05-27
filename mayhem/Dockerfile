FROM swift:5.8-jammy as builder
ADD . /src
WORKDIR /src/mayhem
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libgd-dev && rm -rf /var/lib/apt/lists/*
RUN swift build -c release -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library

FROM swift:5.8-jammy-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libgd3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/mayhem/.build/release /release
COPY --from=builder /src/mayhem/testsuite /testsuite
ENV ASAN_OPTIONS detect_leaks=0
ENTRYPOINT ["/release/GDFuzz"]
