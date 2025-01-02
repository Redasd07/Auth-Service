# Use Maven image to build the project
FROM maven:3.8.4-openjdk-17-slim as build

# Set the working directory
WORKDIR /app

# Copy the pom.xml and the source code
COPY pom.xml /app
COPY src /app/src

# Run the Maven build
RUN mvn clean package -DskipTests

# Use a slim JDK 17 image for the runtime
FROM openjdk:17-jdk-slim as authservice

# Set the working directory for the application
WORKDIR /app

# Copy the built JAR file from the build stage
COPY --from=build /app/target/demo-0.0.1-SNAPSHOT.jar /app/authservice.jar

# Set the entry point to run the JAR file
ENTRYPOINT ["java", "-jar", "/app/authservice.jar"]
