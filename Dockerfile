# Use Java 18 as the base
FROM openjdk:18-jdk-alpine

# Creating and setting the working dir
WORKDIR /usr/src/app

# Setting up the user
ARG UID=1000
ARG GID=1000
RUN addgroup -g $GID antivpn && adduser -D -u $UID -G antivpn antivpn
RUN chown -R antivpn:antivpn /usr/src/app
USER antivpn

# Moving the jar file to the container
COPY AntiVPN.jar application.jar

# Expose the port
EXPOSE 7500

# Run the app
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "application.jar"]