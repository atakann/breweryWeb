# BreweryBook Web Application

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
  - [Using Docker](#using-docker)
- [API Endpoints](#api-endpoints)
- [Example API Usage](#example-api-usage)
- [Swagger Documentation](#swagger-documentation)

## Overview

BreweryBook is a web application that allows users to register, login and then query breweries from OpenBreweryDB.

## Getting Started

### Using Docker

To run BreweryBook using Docker, follow these steps:

1. Clone the repository:
    ```bash
    git clone [your-repo-link]
    cd [your-repo-name]
    ```

2. Build the Docker image:
    ```bash
    docker-compose build
    ```

3. Run the application:
    ```bash
    docker-compose up
    ```

And now while the docker is running, in another terminal run the following command to setup the database

4. Run migrations to set up the database:
    ```
    docker-compose exec web python manage.py migrate
    ```

The app should now be running at `http://localhost:8000/` in your browser.

## API Endpoints

There are three endpoints.

### User Endpoints:

1. **Endpoint**: `/register/`
    **Method**: POST

    **Description**: Register a new user.

    **Request Body**:
    - **username**: Desired username for the new account.
    - **password**: Password for the new account.

    **Responses**:
    - 201: User created successfully.
    - 400: Username already exists or invalid data.
    - 500: Internal server error.


2. **Endpoint**: `/login/`
    **Method**: POST

    **Description**: Authenticate and obtain JWT for a user.

    **Request Body**:
    - **username**: Username of the account.
    - **password**: Password of the account.

    **Responses**:
    - 200: Successful authentication, returns a JWT.
    - 400: Invalid credentials.
    - 500: Internal server error.


### Brewery Endpoints:

**Endpoint**: `/breweries/`
**Method**: GET

**Description**: Get a list of breweries based on the provided query parameters.

**Some of the Query Parameters**:
- **by_type**: Filter breweries by type (e.g., micro, nano).
- **by_city**: Filter breweries by city.
- **by_name**: Filter breweries by name.

**Headers**:
- **Authorization**: Bearer token for authentication. Use like "Bearer token".

## Example API Usage

Below are example usages of the main API endpoints:

1. **User Registration**:

    - Endpoint: `/register/`
    - Method: `POST`
    - Payload:
      ```json
      {
          "username": "john_doe",
          "password": "securepassword123"
      }
      ```

    - Response (Success):
      ```json
      {
          "success": "User created successfully"
      }
      ```

    - Response (Error - Username taken):
      ```json
      {
          "error": "Username is already taken."
      }
      ```

2. **User Login**:

    - Endpoint: `/login/`
    - Method: `POST`
    - Payload:
      ```json
      {
          "username": "john_doe",
          "password": "securepassword123"
      }
      ```

    - Response (Success):
      ```json
      {
          "token": "abc123xyz456"
      }
      ```

    - Response (Error - Invalid credentials):
      ```json
      {
          "error": "Invalid username or password."
      }
      ```

3. **Query a Brewery/Breweries**:

    - Endpoint: `/breweries/?by_type=micro&per_page=1`
    - Method: `GET`
    - Headers:
      ```
      Authorization: Bearer abc123xyz456
      ```
    
    - Payload:
      Need Authorization Header with key=Authorization and value=Bearer <token-id>

    - Response (Success):
      ```json
        {
            "id": "5128df48-79fc-4f0f-8b52-d06be54d0cec",
            "name": "(405) Brewing Co",
            "brewery_type": "micro",
            "address_1": "1716 Topeka St",
            "address_2": null,
            "address_3": null,
            "city": "Norman",
            "state_province": "Oklahoma",
            "postal_code": "73069-8224",
            "country": "United States",
            "longitude": "-97.46818222",
            "latitude": "35.25738891",
            "phone": "4058160490",
            "website_url": "http://www.405brewing.com",
            "state": "Oklahoma",
            "street": "1716 Topeka St"
        }
      ```

    - Response (Error - Missing token):
      ```json
        {
            "detail": "Authorization token not provided"
        }
      ```

## Swagger Documentation

BreweryBook provides comprehensive Swagger documentation for its API. Swagger offers an interactive interface where you can learn about the API's endpoints, make requests, and see responses.

**How to Access**:

1. Start the BreweryBook application.
2. Open your web browser.
3. Navigate to `http://localhost:8000/swagger/`.

You'll be presented with a list of available API endpoints, details about required parameters, and the expected responses. You can also "try out" each endpoint directly from the interface.

**Features**:

- **Interactive UI**: Test any endpoint directly from the browser.
- **Model Schemas**: Understand the structure of request payloads and responses.
- **Endpoint Details**: Learn about the methods (GET, POST, PUT, DELETE), parameters, and more.
