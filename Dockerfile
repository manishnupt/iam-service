FROM maven:3.8.4-openjdk-17-slim AS maven_cache

# Set the working directory in the container
WORKDIR /app

COPY pom.xml .

COPY src ./src
COPY target/iam-service-0.0.1-SNAPSHOT.jar .
# Expose the port that the Spring Boot application will run on
EXPOSE 7077

# Define the command to run the Spring Boot application when the container starts
CMD ["java", "-jar", "iam-service-0.0.1-SNAPSHOT.jar"]