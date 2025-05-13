# Financial News API Documentation

This API provides various endpoints to fetch financial news articles for companies from our database. The API supports filtering by company symbol, company name, date ranges, article types, and sentiment analysis.

## Base URL

```
http://localhost:7071/api/function_app
```

## Endpoints

All endpoints follow the same pattern with different query parameters.

### Company Filtering

#### Get news by company symbol

Retrieve news articles for a specific company using its stock symbol.

```
GET /api/function_app?symbol={symbol}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS
```

#### Get news by company name

Retrieve news articles by searching for a company name (returns news for any company with name containing the search term).

```
GET /api/function_app?company={company_name}
```

**Examples:**
```
http://localhost:7071/api/function_app?company=Tata%20Consultancy%20Services
http://localhost:7071/api/function_app?company=Tata
```

### Content Filtering

#### Filter by sentiment

Retrieve news articles with specific sentiment analysis results.

```
GET /api/function_app?symbol={symbol}&sentiment={sentiment}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS&sentiment=positive
```

#### Filter by article type

Retrieve news articles of a specific type.

```
GET /api/function_app?symbol={symbol}&type={article_type}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS&type=Strategic%20Actions
```

#### Combined content filters

Combine multiple content filters in a single request.

```
GET /api/function_app?symbol={symbol}&type={article_type}&sentiment={sentiment}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS&type=Strategic%20Actions&sentiment=negative
```

### Date Range Filtering

#### Filter by date range (UTC format)

Retrieve news articles within a specific date range using UTC format.

```
GET /api/function_app?symbol={symbol}&from={from_date}&to={to_date}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS&from=2025-05-09T00:00:00Z&to=2025-05-12T23:59:59Z
```

#### Filter by date range (with timezone offset)

Retrieve news articles within a specific date range using timezone-aware format.

```
GET /api/function_app?symbol={symbol}&from={from_date}&to={to_date}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS&from=2025-05-05T00:00:00%2B05:30&to=2025-05-11T23:59:59%2B05:30
```

### Pagination

#### Limit and offset pagination

Control the number of results returned and skip a certain number of records.

```
GET /api/function_app?symbol={symbol}&limit={limit}&offset={offset}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS&limit=5&offset=10
```

### Other Filters

#### Filter by article link

Retrieve a specific article by its link.

```
GET /api/function_app?symbol={symbol}&link={link}
```

**Example:**
```
http://localhost:7071/api/function_app?symbol=TCS&link=https://www.youtube.com
```

## Response Format

All successful responses return a JSON array of article objects. Each article contains:

- `id`: Unique identifier for the article
- `created_at`: Timestamp when the article was added to the database
- `title`: Article title
- `link`: URL to the article
- `date`: Publication date of the article
- `summary`: Brief summary of the article content
- `company`: Company name
- `article_type`: Type of article (e.g., "Strategic Actions")
- `sentiment`: Sentiment analysis result (e.g., "positive", "negative", "neutral")


# API Error Messages

## 400 Bad Request
These errors occur when the request contains invalid parameters or parameter combinations.

| Error Message | Description |
|---------------|-------------|
| "Use only one of: symbol, isin, company" | Returned when more than one company identifier is used in the same request. You must use only one of these parameters. |
| "'from' date must be before 'to' date" | Returned when the provided date range is invalid because the start date is after the end date. |
| "Invalid date format: {specific error}. Use ISO 8601 format (e.g., 2023-01-01T00:00:00+05:30)" | Returned when dates are not provided in ISO 8601 format. The specific parsing error will be included in the message. |
| "limit/offset must be non-negative integers" | Returned when pagination parameters are not valid numbers or when negative values are provided. |

## 404 Not Found
These errors occur when the requested resource does not exist in the database.

| Error Message | Description |
|---------------|-------------|
| "Company with symbol '{symbol}' not found" | Returned when the provided company symbol does not exist in the database. |
| "Company with ISIN '{isin}' not found" | Returned when the provided ISIN does not exist in the database. |
| "No companies found with name containing '{company}'" | Returned when no companies match the provided company name search term. |

## 500 Internal Server Error
These errors indicate server-side issues that prevent the request from being fulfilled.

| Error Message | Description |
|---------------|-------------|
| "Server configuration error" | Returned when required environment variables (SUPABASE_URL, SUPABASE_KEY) are not set. |
| "Database connection error" | Returned when the API cannot establish a connection to the Supabase database. |
| "Internal server error" | Generic error returned when an unexpected exception occurs during request processing. |

## Example Error Response

```json
{
  "error": "Invalid date format: Invalid isoformat string. Use ISO 8601 format (e.g., 2023-01-01T00:00:00+05:30)"
}
```