# syntax=docker/dockerfile:1

# The jar is platform independent, so always build on the native platform
FROM --platform=$BUILDPLATFORM maven:3-eclipse-temurin-24 AS build
WORKDIR /build
COPY pom.xml ./
COPY src/ src/
RUN --mount=type=cache,target=/root/.m2 mvn -B -q package -DskipTests

FROM eclipse-temurin:24-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system antivpn \
    && useradd --system --gid antivpn --home-dir /app antivpn

WORKDIR /app
COPY --from=build /build/target/AntiVPN.jar application.jar
RUN mkdir -p data maxmind logs config && chown -R antivpn:antivpn /app
USER antivpn

# data: source snapshots, maxmind: GeoLite2 databases
VOLUME ["/app/data", "/app/maxmind"]
EXPOSE 7500

# Liveness only, so a Redis or InfluxDB outage doesn't restart the container
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fsS http://localhost:7500/actuator/health/liveness || exit 1

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "application.jar"]
