# Use Java 18 as the base
FROM openjdk:18-jdk-alpine

# Creating and setting the working dir
WORKDIR /usr/src/app

# Moving the jar file to the container
COPY AntiVPN.jar application.jar

# Expose the port
EXPOSE 7500

# Run the app
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "application.jar"]