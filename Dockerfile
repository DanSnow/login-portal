# use the official Bun image
# see all versions at https://hub.docker.com/r/oven/bun/tags
FROM oven/bun:1 as base
WORKDIR /usr/src/app

# install dependencies into temp directory
# this will cache them and speed up future builds
FROM base AS web

RUN mkdir -p packages/web
COPY package.json bun.lockb /usr/src/app/
COPY packages/web/package.json /usr/src/app/packages/web/
RUN cd /usr/src/app && bun install --frozen-lockfile

COPY packages/web/* packages/web/
COPY packages/web/src packages/web/src
RUN cd /usr/src/app/packages/web && bun run build

FROM rust:1.75 AS app

COPY Cargo.toml Cargo.lock /app/
COPY src /app/src
RUN mkdir -p /app/packages/web
COPY --from=web /usr/src/app/packages/web/dist /app/packages/web/dist
RUN cd /app && cargo build --release


FROM gcr.io/distroless/cc-debian12

COPY --from=app /app/target/release/login-portal /login-portal

ENTRYPOINT ["/login-portal"]
